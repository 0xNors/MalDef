/**
 * MCK-Guard Packer Detector - Stronger detection, type-aware
 */

export interface PackerResult {
  isPacked: boolean;
  packer: string | null;
  confidence: number;
  riskScore: number;
  findings: any[];
  fileTypeInfo?: any;
}

export function detectPacker(
  buffer: Buffer,
  entropy: { overall: number; sections: { name: string; entropy: number; size: number }[] },
  fileTypeInfo: { isCompressed: boolean; isPE: boolean; isDocument: boolean; mimeType: string }
): PackerResult {
  const findings: any[] = [];
  let isPacked = false;
  let packer: string | null = null;
  let confidence = 0;
  let riskScore = 0;

  const overallEntropy = entropy.overall;
  const isPE = fileTypeInfo.isPE;
  const isCompressed = fileTypeInfo.isCompressed;
  const isDocument = fileTypeInfo.isDocument;

  // Type-aware: compressed files (PDF, ZIP, DOCX, etc.) high entropy is NORMAL, not packing
  if (isCompressed && !isPE) {
    return {
      isPacked: false,
      packer: null,
      confidence: 0,
      riskScore: 0,
      findings: [],
      fileTypeInfo
    };
  }

  // For PE files, check entropy and sections
  if (isPE) {
    // Check overall entropy
    if (overallEntropy > 7.6) {
      isPacked = true;
      packer = overallEntropy > 7.9 ? 'High Entropy Packer' : 'Possible Packer';
      confidence = overallEntropy > 7.9 ? 85 : 65;
      riskScore = overallEntropy > 7.9 ? 35 : 20;
      findings.push({
        category: 'Packing',
        severity: overallEntropy > 7.9 ? 'HIGH' : 'MEDIUM',
        title: `High Entropy PE: ${overallEntropy}`,
        description: `PE file shows high entropy ${overallEntropy} indicating possible packing`,
        evidence: `Overall entropy: ${overallEntropy}, Size: ${buffer.length}`,
        score: riskScore
      });
    }

    // Check section entropies
    const highEntropySections = entropy.sections.filter(s => s.entropy > 7.2 && s.size > 1024);
    if (highEntropySections.length >= 2) {
      isPacked = true;
      packer = packer || 'Section Packing';
      confidence = Math.max(confidence, 70);
      riskScore = Math.max(riskScore, 25);
      findings.push({
        category: 'Section Analysis',
        severity: 'MEDIUM',
        title: `Suspicious Sections: ${highEntropySections.length}`,
        description: `${highEntropySections.length} sections with high entropy`,
        evidence: highEntropySections.map(s => `${s.name}: ${s.entropy}`).join(', '),
        score: 15
      });
    }

    // Check for small PE (possible dropper) - not packed but suspicious
    if (buffer.length < 10 * 1024) {
      findings.push({
        category: 'Small Executable',
        severity: 'MEDIUM',
        title: 'Small PE - Possible Dropper',
        description: `Very small PE ${buffer.length} bytes - typical for droppers/loaders`,
        evidence: `Size: ${buffer.length} bytes, Entropy: ${overallEntropy}`,
        score: 12
      });
      // Don't mark as packed, but add risk
      riskScore = Math.max(riskScore, 12);
    }

    // Check for overlay data (common in packed files)
    const peSigOffset = buffer.length > 0x3C ? buffer.readUInt32LE(0x3C) : 0;
    if (peSigOffset > 0 && peSigOffset < buffer.length) {
      // Rough check for overlay - if file larger than expected
      const expectedSize = peSigOffset + 1024; // simplified
      if (buffer.length > expectedSize + 1024 * 100) {
        findings.push({
          category: 'Overlay',
          severity: 'LOW',
          title: 'Possible Overlay Data',
          description: 'File has extra data beyond PE structure',
          evidence: `File size ${buffer.length} larger than expected`,
          score: 5
        });
      }
    }
  }

  // For non-PE, non-compressed files with high entropy
  if (!isPE && !isCompressed && overallEntropy > 7.2) {
    findings.push({
      category: 'Obfuscation',
      severity: overallEntropy > 7.6 ? 'HIGH' : 'MEDIUM',
      title: `High Entropy: ${overallEntropy}`,
      description: `File shows high entropy ${overallEntropy} - possible obfuscation`,
      evidence: `Entropy: ${overallEntropy}, Type: ${fileTypeInfo.mimeType}`,
      score: overallEntropy > 7.6 ? 20 : 10
    });
    riskScore = Math.max(riskScore, overallEntropy > 7.6 ? 20 : 10);
  }

  return {
    isPacked,
    packer,
    confidence,
    riskScore: Math.min(riskScore, 100),
    findings,
    fileTypeInfo
  };
}
