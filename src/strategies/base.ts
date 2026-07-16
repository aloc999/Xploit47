import { AttackNode, ReasoningRequest, ReasoningResponse } from '../types.js';
import { StateManager } from '../state.js';

export interface StrategyMetrics {
  name: string;
  nodesExplored: number;
  averageScore: number;
  maxDepth: number;
  active?: boolean;
  [key: string]: number | string | boolean | undefined;
}

export abstract class BaseStrategy {
  protected stateManager: StateManager;
  protected nodes: Map<string, AttackNode> = new Map();
  protected readonly minScore = 0.5;

  constructor(stateManager: StateManager) {
    this.stateManager = stateManager;
    this.nodes = new Map();
  }

  abstract processAttackStep(request: ReasoningRequest): Promise<ReasoningResponse>;

  protected async getNode(id: string): Promise<AttackNode | undefined> {
    return this.nodes.get(id) ?? this.stateManager.getNode(id);
  }

  protected async saveNode(node: AttackNode): Promise<void> {
    this.nodes.set(node.id, node);
  }

  protected evaluateAttackStep(node: AttackNode, parent?: AttackNode): number {
    let score = this.minScore;

    score += this.calculateLogicalScore(node);
    score += this.calculatePentestScore(node);
    score -= this.calculateDepthPenalty(node);

    if (parent) {
      score += this.calculateCoherence(parent.attackStep, node.attackStep);
    }

    return Math.min(Math.max(score, 0), 1);
  }

  private calculateLogicalScore(node: AttackNode): number {
    let score = 0;

    // Length score (up to 0.2) — favor detailed steps
    score += Math.min(node.attackStep.length / 250, 0.2);

    // Logical connectors
    if (/\b(therefore|because|if|then|thus|hence|so|after|then)\b/i.test(node.attackStep)) {
      score += 0.1;
    }

    // Technical content / operators
    if (/[+\-*/=<>]|port\s*\d+|0x[0-9a-f]+/i.test(node.attackStep)) {
      score += 0.1;
    }

    return score;
  }

  /** Pentest-oriented heuristics (aligned with ToT engine intent) */
  private calculatePentestScore(node: AttackNode): number {
    let score = 0;
    const text = node.attackStep;

    if (/domain controller|active directory|kerberos|ntlm/i.test(text)) score += 0.15;
    if (/database|sql|mongodb|redis/i.test(text)) score += 0.1;
    if (/CVE-\d{4}-\d{4,7}/i.test(text)) score += 0.15;
    if (/\b(critical|high severity|rce|remote code)\b/i.test(text)) score += 0.1;
    if (/\b(nmap|enum4linux|smb|ssh|http|https|ldap|rdp)\b/i.test(text)) score += 0.1;
    if (/\b(privesc|privilege escalation|linpeas|winpeas|sudo)\b/i.test(text)) score += 0.1;
    if (/\b(exploit|payload|shell|reverse shell)\b/i.test(text)) score += 0.05;

    return Math.min(score, 0.4);
  }

  private calculateDepthPenalty(node: AttackNode): number {
    return Math.min((node.depth || 0) * 0.05, 0.25);
  }

  private calculateCoherence(parentAttackStep: string, childAttackStep: string): number {
    const parentTerms = new Set(
      parentAttackStep.toLowerCase().split(/\W+/).filter((t) => t.length > 2)
    );
    const childTerms = childAttackStep
      .toLowerCase()
      .split(/\W+/)
      .filter((t) => t.length > 2);
    if (parentTerms.size === 0 || childTerms.length === 0) return 0;
    const overlap = childTerms.filter((term) => parentTerms.has(term)).length;
    return Math.min(overlap * 0.05, 0.2);
  }

  public async getBestPath(): Promise<AttackNode[]> {
    const nodes = await this.stateManager.getAllNodes();
    if (nodes.length === 0) return [];

    const completedNodes = nodes
      .filter((n) => n.isComplete)
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0));

    if (completedNodes.length === 0) {
      const best = [...nodes].sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];
      return best ? this.stateManager.getPath(best.id) : [];
    }

    return this.stateManager.getPath(completedNodes[0].id);
  }

  public async getMetrics(): Promise<StrategyMetrics> {
    const nodes = await this.stateManager.getAllNodes();

    return {
      name: this.constructor.name,
      nodesExplored: nodes.length,
      averageScore:
        nodes.length > 0
          ? nodes.reduce((sum, n) => sum + (n.score ?? 0), 0) / nodes.length
          : 0,
      maxDepth: nodes.length > 0 ? Math.max(...nodes.map((n) => n.depth)) : 0,
    };
  }

  public async clear(): Promise<void> {
    this.nodes.clear();
  }
}
