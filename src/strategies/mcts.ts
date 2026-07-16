import { v4 as uuidv4 } from 'uuid';
import { AttackNode, ReasoningRequest, ReasoningResponse, CONFIG } from '../types.js';
import { BaseStrategy } from './base.js';
import { StateManager } from '../state.js';

interface MCTSNode extends AttackNode {
  visits: number;
  ucb1Score?: number;
}

export class MCTSStrategy extends BaseStrategy {
  private readonly explorationConstant = Math.sqrt(2);
  private readonly simulationDepth = 3;

  constructor(stateManager: StateManager) {
    super(stateManager);
  }

  public async processAttackStep(request: ReasoningRequest): Promise<ReasoningResponse> {
    // Root represents the caller's real attack step (never return simulated text as the step)
    const rootNode: MCTSNode = {
      id: uuidv4(),
      attackStep: request.attackStep,
      depth: request.attackStepNumber - 1,
      visits: 0,
      score: 0,
      isComplete: !request.nextAttackStepNeeded,
    };

    rootNode.score = this.evaluateAttackStep(rootNode);
    await this.saveNode(rootNode);
    await this.stateManager.saveNode(rootNode);

    // Run MCTS iterations to refine score via tree search
    for (let i = 0; i < CONFIG.mctsIterations; i++) {
      const selectedNode = await this.select(rootNode);
      const expandedNode = await this.expand(selectedNode);
      const simulationScore = await this.simulate(expandedNode);
      await this.backpropagate(expandedNode, simulationScore);
    }

    // Prefer best child score if available; always return the user's attackStep
    const bestChild = await this.getBestChild(rootNode);
    const finalScore = bestChild
      ? (bestChild.score ?? rootNode.score ?? 0)
      : (rootNode.score ?? 0);

    // Keep root score aligned with tree result for stats/path APIs
    rootNode.score = finalScore;
    await this.saveNode(rootNode);
    await this.stateManager.saveNode(rootNode);

    return {
      nodeId: rootNode.id,
      attackStep: rootNode.attackStep,
      score: finalScore,
      strategyUsed: 'mcts',
      nextAttackStepNeeded: request.nextAttackStepNeeded,
    };
  }

  private async select(node: MCTSNode): Promise<MCTSNode> {
    let current = node;
    while (Array.isArray(current.children) && current.children.length > 0) {
      const next = await this.selectBestUCB1(current);
      if (!next) break;
      current = next;
    }
    return current;
  }

  private async expand(node: MCTSNode): Promise<MCTSNode> {
    const newNode: MCTSNode = {
      id: uuidv4(),
      attackStep: `Simulated attack step at depth ${(node.depth || 0) + 1}`,
      depth: (node.depth || 0) + 1,
      visits: 0,
      score: 0,
      isComplete: false,
      parent: node,
    };

    newNode.score = this.evaluateAttackStep(newNode, node);
    await this.saveNode(newNode);
    await this.stateManager.saveNode(newNode);

    if (!node.children) node.children = [];
    node.children.push(newNode);
    await this.saveNode(node);
    await this.stateManager.saveNode(node);

    return newNode;
  }

  private async simulate(node: MCTSNode): Promise<number> {
    let current = node;
    let totalScore = current.score || 0;

    for (let depth = 0; depth < this.simulationDepth; depth++) {
      const simulatedNode: MCTSNode = {
        id: `sim-${uuidv4()}`,
        attackStep: `Random attack simulation at depth ${depth + 1}`,
        depth: (current.depth || 0) + 1,
        visits: 1,
        score: 0,
        isComplete: depth === this.simulationDepth - 1,
      };

      simulatedNode.score = this.evaluateAttackStep(simulatedNode, current);
      totalScore += simulatedNode.score || 0;
      current = simulatedNode;
    }

    return totalScore / (this.simulationDepth + 1);
  }

  private async backpropagate(node: MCTSNode, score: number) {
    let current: MCTSNode | undefined = node;

    while (current) {
      current.visits = (current.visits || 0) + 1;
      if (current.score !== undefined) {
        current.score =
          (current.score * (current.visits - 1) + score) / current.visits;
      }
      current = current.parent as MCTSNode | undefined;
    }
  }

  private async selectBestUCB1(node: MCTSNode): Promise<MCTSNode | undefined> {
    const children = (node.children || []).filter(
      (c): c is MCTSNode => typeof (c as MCTSNode).visits === 'number'
    );
    if (children.length === 0) return undefined;

    const totalVisits = Math.max(node.visits || 1, 1);
    for (const child of children) {
      const exploitation = child.score || 0;
      const exploration = Math.sqrt(
        Math.log(totalVisits) / Math.max(child.visits || 1, 1)
      );
      child.ucb1Score = exploitation + this.explorationConstant * exploration;
    }
    return children.reduce((a, b) =>
      (a.ucb1Score || 0) > (b.ucb1Score || 0) ? a : b
    );
  }

  private async getBestChild(node: MCTSNode): Promise<MCTSNode | undefined> {
    const children = (node.children || []).filter(
      (c): c is MCTSNode => typeof (c as MCTSNode).visits === 'number'
    );
    if (children.length === 0) return undefined;
    return children.reduce((a, b) => (a.visits > b.visits ? a : b));
  }

  private calculatePathScore(path: AttackNode[]): number {
    if (path.length === 0) return 0;
    return path.reduce((sum, n) => sum + (n.score || 0), 0) / path.length;
  }

  public async getBestPath(): Promise<AttackNode[]> {
    const nodes = Array.from(this.nodes.values());
    if (nodes.length === 0) return [];

    const completePaths = this.findCompletePaths(nodes);
    if (completePaths.length === 0) {
      // Fall back to highest-scoring single node path
      const best = [...nodes].sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];
      return best ? this.constructPath(best) : [];
    }

    return completePaths.reduce((bestPath, currentPath) =>
      this.calculatePathScore(currentPath) > this.calculatePathScore(bestPath)
        ? currentPath
        : bestPath
    );
  }

  private findCompletePaths(nodes: AttackNode[]): AttackNode[][] {
    const endNodes = nodes.filter((n) => n.isComplete);
    return endNodes.map((end) => this.constructPath(end));
  }

  private constructPath(endNode: AttackNode): AttackNode[] {
    const path: AttackNode[] = [];
    let current: AttackNode | undefined = endNode;

    while (current) {
      path.unshift(current);
      current = current.parent;
    }

    return path;
  }
}
