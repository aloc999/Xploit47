import {
  AttackNode,
  ReasoningRequest,
  ReasoningResponse,
  ReasoningStats,
  CONFIG,
  ReasoningStrategy,
} from "./types.js";
import { StateManager } from "./state.js";
import { StrategyFactory } from "./strategies/factory.js";
import { BaseStrategy, StrategyMetrics } from "./strategies/base.js";
import { scorePath } from "./scoring.js";

export class Reasoner {
  private stateManager: StateManager;
  private currentStrategy: BaseStrategy;
  private strategies: Map<ReasoningStrategy, BaseStrategy>;
  /** Last user node id for each step number — accurate auto parent chaining */
  private lastNodeByStep = new Map<number, string>();
  private lastNodeId?: string;

  constructor() {
    this.stateManager = new StateManager(CONFIG.cacheSize);

    this.strategies = new Map();
    this.strategies.set(
      ReasoningStrategy.BEAM_SEARCH,
      StrategyFactory.createStrategy(
        ReasoningStrategy.BEAM_SEARCH,
        this.stateManager
      )
    );
    this.strategies.set(
      ReasoningStrategy.MCTS,
      StrategyFactory.createStrategy(ReasoningStrategy.MCTS, this.stateManager)
    );

    const defaultStrategy = CONFIG.defaultStrategy as ReasoningStrategy;
    this.currentStrategy =
      this.strategies.get(defaultStrategy) ||
      this.strategies.get(ReasoningStrategy.BEAM_SEARCH)!;
  }

  public async processAttackStep(
    request: ReasoningRequest
  ): Promise<ReasoningResponse> {
    // Switch strategy if requested
    if (
      request.strategyType &&
      this.strategies.has(request.strategyType as ReasoningStrategy)
    ) {
      this.currentStrategy = this.strategies.get(
        request.strategyType as ReasoningStrategy
      )!;
    }

    // Auto-link parent for sequential chains when caller omits parentId
    const enriched: ReasoningRequest = { ...request };
    if (!enriched.parentId) {
      if (enriched.attackStepNumber > 1) {
        enriched.parentId =
          this.lastNodeByStep.get(enriched.attackStepNumber - 1) ??
          this.lastNodeId;
      }
    }

    const response = await this.currentStrategy.processAttackStep(enriched);

    // Track for next auto-parent
    this.lastNodeByStep.set(enriched.attackStepNumber, response.nodeId);
    this.lastNodeId = response.nodeId;

    return {
      ...response,
      strategyUsed: this.getCurrentStrategyName(),
    };
  }

  public async getStats(): Promise<ReasoningStats> {
    const all = await this.stateManager.getAllNodes();
    const nodes = all.filter((n) => !n.isSimulation);

    if (nodes.length === 0) {
      return {
        totalNodes: 0,
        userNodes: 0,
        averageScore: 0,
        maxDepth: 0,
        branchingFactor: 0,
        bestPathScore: 0,
        strategyMetrics: {},
      };
    }

    const scores = nodes.map((n) => n.score ?? 0);
    const depths = nodes.map((n) => n.depth);
    const branchingFactors = nodes.map(
      (n) => (n.children || []).filter((c) => !c.isSimulation).length
    );

    const bestPath = await this.getBestPath();
    const bestPathScore = scorePath(bestPath.map((n) => n.score ?? 0));

    const metrics = await this.getStrategyMetrics();

    const round4 = (n: number) => Math.round(n * 10000) / 10000;

    return {
      totalNodes: nodes.length,
      userNodes: nodes.length,
      averageScore: round4(
        scores.reduce((a, b) => a + b, 0) / scores.length
      ),
      maxDepth: Math.max(...depths),
      branchingFactor: round4(
        branchingFactors.reduce((a, b) => a + b, 0) / nodes.length
      ),
      bestPathScore,
      strategyMetrics: metrics,
    };
  }

  private async getStrategyMetrics(): Promise<
    Record<string, StrategyMetrics>
  > {
    const metrics: Record<string, StrategyMetrics> = {};

    for (const [name, strategy] of this.strategies.entries()) {
      metrics[name] = await strategy.getMetrics();
      if (strategy === this.currentStrategy) {
        metrics[name] = {
          ...metrics[name],
          active: true,
        };
      }
    }

    return metrics;
  }

  public getCurrentStrategyName(): ReasoningStrategy {
    for (const [name, strategy] of this.strategies.entries()) {
      if (strategy === this.currentStrategy) {
        return name;
      }
    }
    return ReasoningStrategy.BEAM_SEARCH;
  }

  public async getBestPath(): Promise<AttackNode[]> {
    return this.currentStrategy.getBestPath();
  }

  public async clear(): Promise<void> {
    this.stateManager.clear();
    this.lastNodeByStep.clear();
    this.lastNodeId = undefined;
    for (const strategy of this.strategies.values()) {
      await strategy.clear();
    }
  }

  public setStrategy(strategyType: ReasoningStrategy): void {
    if (!this.strategies.has(strategyType)) {
      throw new Error(`Unknown strategy type: ${strategyType}`);
    }
    this.currentStrategy = this.strategies.get(strategyType)!;
  }

  public getAvailableStrategies(): ReasoningStrategy[] {
    return Array.from(this.strategies.keys());
  }
}
