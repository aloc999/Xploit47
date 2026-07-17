/**
 * Lightweight beam engine (standalone helper).
 * Uses the same deterministic scorer as the MCP strategies.
 */
import {
  classifyPhase,
  scoreAttackStep,
  scorePath,
  type KillChainPhase,
} from "./scoring.js";

interface AttackNode {
  attackStep: string;
  attackStepNumber: number;
  totalAttackSteps: number;
  nextAttackStepNeeded: boolean;
  score?: number;
  phase?: KillChainPhase;
  children: AttackNode[];
  parent?: AttackNode;
}

export class Engine {
  private attackSteps: AttackNode[] = [];
  private readonly beamWidth = 3;

  public addAttackStep(
    attackStep: string,
    attackStepNumber: number,
    totalAttackSteps: number,
    nextAttackStepNeeded: boolean
  ): AttackNode {
    const node: AttackNode = {
      attackStep,
      attackStepNumber,
      totalAttackSteps,
      nextAttackStepNeeded,
      score: 0,
      children: [],
    };

    let parent: AttackNode | undefined;
    if (this.attackSteps.length > 0) {
      const potentialParents = this.attackSteps.filter(
        (t) => t.attackStepNumber === attackStepNumber - 1
      );
      if (potentialParents.length > 0) {
        parent = potentialParents.reduce((a, b) =>
          (a.score ?? 0) > (b.score ?? 0) ? a : b
        );
        node.parent = parent;
        parent.children.push(node);
      }
    }

    const { score, phase } = scoreAttackStep({
      attackStep,
      attackStepNumber,
      totalAttackSteps,
      parentAttackStep: parent?.attackStep,
      parentPhase: parent?.phase,
    });
    node.score = score;
    node.phase = phase;

    // Keep beam width best attack steps at each level
    const sameLevel = this.attackSteps.filter(
      (t) => t.attackStepNumber === attackStepNumber
    );
    sameLevel.push(node);
    if (sameLevel.length > this.beamWidth) {
      sameLevel.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
      // Remove excess from master list (nodes not in top beam at this level)
      const keep = new Set(sameLevel.slice(0, this.beamWidth));
      this.attackSteps = this.attackSteps.filter(
        (t) => t.attackStepNumber !== attackStepNumber || keep.has(t)
      );
    }

    this.attackSteps.push(node);
    return node;
  }

  public getBestPath(): AttackNode[] {
    const bestLast = [...this.attackSteps]
      .filter((t) => !t.nextAttackStepNeeded)
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];

    if (!bestLast) {
      // fall back to highest scoring node
      const best = [...this.attackSteps].sort(
        (a, b) => (b.score ?? 0) - (a.score ?? 0)
      )[0];
      if (!best) return [];
      return this.reconstruct(best);
    }

    return this.reconstruct(bestLast);
  }

  private reconstruct(end: AttackNode): AttackNode[] {
    const path: AttackNode[] = [end];
    let current = end;
    while (current.parent) {
      path.unshift(current.parent);
      current = current.parent;
    }
    return path;
  }

  public getStats() {
    if (this.attackSteps.length === 0) {
      return {
        totalAttackSteps: 0,
        bestScore: 0,
        averageScore: 0,
        branchingFactor: 0,
        pathScore: 0,
        phases: [] as KillChainPhase[],
      };
    }
    const path = this.getBestPath();
    return {
      totalAttackSteps: this.attackSteps.length,
      bestScore: Math.max(...this.attackSteps.map((t) => t.score ?? 0)),
      averageScore:
        this.attackSteps.reduce((a, b) => a + (b.score ?? 0), 0) /
        this.attackSteps.length,
      branchingFactor:
        this.attackSteps.reduce((a, b) => a + (b.children?.length ?? 0), 0) /
        this.attackSteps.length,
      pathScore: scorePath(path.map((n) => n.score ?? 0)),
      phases: this.attackSteps.map((n) => n.phase ?? classifyPhase(n.attackStep)),
    };
  }
}
