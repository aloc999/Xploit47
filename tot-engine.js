/**
 * Xploit47 Tree-of-Thought engine (standalone helper)
 * Beam-search style expansion for attack-path planning.
 * Scoring is deterministic (no Math.random).
 */
export class ToTEngine {
  constructor() {
    this.beamWidth = 5;
    this.maxDepth = 3;
  }

  // Deterministic pentest scoring (mirrors src/scoring.ts intent)
  async evaluateAttackStep(attackStep) {
    const desc = attackStep.description || "";
    let score = 0.12;
    if (/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/.test(desc)) score += 0.08;
    if (/domain controller|database/i.test(desc)) score += 0.15;
    if (/CVE-\d{4}-\d{4,7}/i.test(desc)) score += 0.1;
    if (/critical|high/i.test(desc)) score += 0.1;
    if (/\b(nmap|enum|exploit|privesc)\b/i.test(desc)) score += 0.1;
    // tiny stable hash jitter replacement: length-based, deterministic
    score += Math.min(desc.length / 500, 0.05);
    return Math.min(score, 1.0);
  }

  // Generate attack steps with asset tagging
  async generateAttackSteps(context, numSteps = 3) {
    const attackSteps = [];
    const scores = [];
    const assets = ['10.0.0.5', 'webserver', 'database']; // Example assets
    for (let i = 0; i < numSteps; i++) {
      // Simulate attack step generation (planning only — does not execute attacks)
      const asset = assets[i % assets.length];
      const description = `Attack Step ${i + 1} on ${asset} about ${context}`;
      const attackStep = { description, asset };
      const score = await this.evaluateAttackStep(attackStep);
      attackSteps.push(attackStep);
      scores.push(score);
    }
    return { attackSteps, scores };
  }

  async expandPath(path) {
    const lastStep = path[path.length - 1];
    const { attackSteps, scores } = await this.generateAttackSteps(lastStep.description || lastStep);
    return attackSteps.map((attackStep, i) => ({
      path: [...path, attackStep],
      score: scores[i],
      asset: attackStep.asset,
      recommendedTool: this.recommendTool(attackStep)
    }));
  }

  // Recommend a tool based on the attack step
  recommendTool(attackStep) {
    if (/scan|nmap/i.test(attackStep.description)) return 'nmap';
    if (/exploit|CVE/i.test(attackStep.description)) return 'metasploit';
    if (/database/i.test(attackStep.description)) return 'sqlmap';
    return 'manual investigation';
  }

  async search(initialContext) {
    let paths = [{ path: [{ description: initialContext, asset: null }], score: 1.0 }];
    for (let depth = 0; depth < this.maxDepth; depth++) {
      const newPaths = [];
      for (const currentPath of paths) {
        const expansions = await this.expandPath(currentPath.path);
        newPaths.push(...expansions);
      }
      // Keep top k paths based on scores
      paths = newPaths
        .sort((a, b) => b.score - a.score)
        .slice(0, this.beamWidth);
    }
    // Highlight the most critical path
    if (paths.length > 0) paths[0].critical = true;
    return paths;
  }
}