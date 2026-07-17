import { v4 as uuidv4 } from "uuid";
import {
  AttackNode,
  ReasoningRequest,
  ReasoningResponse,
  CONFIG,
} from "../types.js";
import { BaseStrategy } from "./base.js";
import { StateManager } from "../state.js";
import { extractAsset } from "../recommend.js";
import { isCriticalStep } from "../scoring.js";
import { recommendTool } from "../recommend.js";

export class BeamSearchStrategy extends BaseStrategy {
  private beams: Map<number, AttackNode[]>;
  private readonly beamWidth: number;

  constructor(stateManager: StateManager) {
    super(stateManager);
    this.beams = new Map();
    this.beamWidth = CONFIG.beamWidth;
  }

  public async processAttackStep(
    request: ReasoningRequest
  ): Promise<ReasoningResponse> {
    const parent = await this.resolveParent(request);

    const node: AttackNode = {
      id: uuidv4(),
      attackStep: request.attackStep,
      depth: request.attackStepNumber - 1,
      score: 0,
      isComplete: !request.nextAttackStepNeeded,
      isSimulation: false,
      parent,
      parentId: parent?.id,
      attackStepNumber: request.attackStepNumber,
      totalAttackSteps: request.totalAttackSteps,
      children: [],
    };

    const { score, breakdown, phase } = this.evaluateAttackStep(
      node,
      parent,
      request
    );
    node.score = score;
    node.scoreBreakdown = breakdown;
    node.phase = phase;
    node.asset = extractAsset(request.attackStep, request.asset);
    const rec = recommendTool(
      request.attackStep,
      request.recommendedTool,
      phase
    );
    node.recommendedTool = rec.recommendedTool;
    node.critical =
      request.critical === true ? true : isCriticalStep(phase, breakdown);

    await this.saveNode(node);

    if (parent) {
      if (!parent.children) parent.children = [];
      // Avoid duplicate child links
      if (!parent.children.some((c) => c.id === node.id)) {
        parent.children.push(node);
      }
      await this.saveNode(parent);
    }

    // Beam: keep top-k user nodes at this depth
    let beam = this.beams.get(node.depth) || [];
    beam = beam.filter((n) => !n.isSimulation);
    beam.push(node);
    beam.sort((a, b) => (b.score || 0) - (a.score || 0));
    if (beam.length > this.beamWidth) {
      beam = beam.slice(0, this.beamWidth);
    }
    this.beams.set(node.depth, beam);

    const path = await this.getPathFrom(node);
    return this.buildResponse(node, request, "beam_search", path);
  }

  public async getBestPath(): Promise<AttackNode[]> {
    const depths = Array.from(this.beams.keys()).sort((a, b) => b - a);
    if (depths.length === 0) return super.getBestPath();

    for (const depth of depths) {
      const beam = (this.beams.get(depth) || []).filter((n) => !n.isSimulation);
      if (beam.length === 0) continue;

      const complete = beam
        .filter((n) => n.isComplete)
        .sort((a, b) => (b.score || 0) - (a.score || 0));
      const best = complete[0] ?? beam[0];
      if (best) return this.getPathFrom(best);
    }

    return super.getBestPath();
  }

  public async getMetrics(): Promise<any> {
    const baseMetrics = await super.getMetrics();
    const beamNodes = Array.from(this.beams.values())
      .flat()
      .filter((n) => !n.isSimulation);
    return {
      ...baseMetrics,
      beamWidth: this.beamWidth,
      activeBeams: this.beams.size,
      totalBeamNodes: beamNodes.length,
    };
  }

  public async clear(): Promise<void> {
    await super.clear();
    this.beams.clear();
  }
}
