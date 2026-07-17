import type { KillChainPhase, ScoreBreakdown } from "./scoring.js";

export type { KillChainPhase, ScoreBreakdown };

export interface AttackNode {
  id: string;
  attackStep: string;
  depth: number;
  score?: number;
  isComplete?: boolean;
  /** Simulated MCTS expansion — excluded from user-facing stats/paths */
  isSimulation?: boolean;
  phase?: KillChainPhase;
  asset?: string;
  recommendedTool?: string;
  critical?: boolean;
  scoreBreakdown?: ScoreBreakdown;
  attackStepNumber?: number;
  totalAttackSteps?: number;
  children?: AttackNode[];
  parent?: AttackNode;
  parentId?: string;
}

export interface ReasoningRequest {
  attackStep: string;
  attackStepNumber: number;
  totalAttackSteps: number;
  nextAttackStepNeeded: boolean;
  parentId?: string;
  strategyType?: string;
  asset?: string;
  recommendedTool?: string;
  critical?: boolean;
}

export interface ReasoningResponse {
  nodeId: string;
  attackStep: string;
  score: number;
  strategyUsed: string;
  nextAttackStepNeeded: boolean;
  phase: KillChainPhase;
  asset?: string;
  recommendedTool: string;
  toolConfidence: number;
  toolAlternatives: string[];
  toolRationale: string;
  critical: boolean;
  scoreBreakdown: ScoreBreakdown;
  parentId?: string;
  path: Array<{
    nodeId: string;
    attackStep: string;
    score: number;
    phase?: KillChainPhase;
  }>;
  pathScore: number;
  nextStepHints: string[];
}

export interface ReasoningStats {
  totalNodes: number;
  /** User-submitted steps only (excludes MCTS simulations) */
  userNodes: number;
  averageScore: number;
  maxDepth: number;
  branchingFactor: number;
  bestPathScore: number;
  strategyMetrics: Record<string, any>;
}

export const CONFIG = {
  beamWidth: 5,
  maxDepth: 10,
  mctsIterations: 50,
  temperature: 0.7,
  cacheSize: 1000,
  defaultStrategy: "beam_search",
} as const;

export enum ReasoningStrategy {
  BEAM_SEARCH = "beam_search",
  MCTS = "mcts",
}
