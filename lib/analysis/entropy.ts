export function calculateEntropy(buffer: Buffer | Uint8Array): number {
  if (buffer.length === 0) return 0;
  
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    freq[buffer[i]]++;
  }
  
  let entropy = 0;
  const len = buffer.length;
  
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  
  return Math.round(entropy * 100) / 100;
}

export function analyzeSections(buffer: Buffer): { name: string; entropy: number; size: number; suspicious: boolean }[] {
  // Simulate section analysis - in real PE parsing we'd parse actual sections
  // For defensive demo, we analyze chunks
  const sections: { name: string; entropy: number; size: number; suspicious: boolean }[] = [];
  const chunkSize = Math.floor(buffer.length / 5) || buffer.length;
  
  const sectionNames = ['.text', '.rdata', '.data', '.rsrc', '.reloc'];
  
  for (let i = 0; i < Math.min(5, Math.ceil(buffer.length / chunkSize)); i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, buffer.length);
    const chunk = buffer.subarray(start, end);
    const entropy = calculateEntropy(chunk);
    
    sections.push({
      name: sectionNames[i] || `.sec${i}`,
      entropy,
      size: chunk.length,
      suspicious: entropy > 7.2
    });
  }
  
  // If buffer small, add synthetic high entropy check
  if (buffer.length < 1024) {
    return [
      { name: '.text', entropy: calculateEntropy(buffer), size: buffer.length, suspicious: calculateEntropy(buffer) > 7.0 }
    ];
  }
  
  return sections;
}

export function getEntropyRiskLevel(entropy: number): { level: string; score: number; description: string } {
  if (entropy >= 7.5) {
    return { level: 'CRITICAL', score: 30, description: 'Very high entropy - possible packing/encryption' };
  }
  if (entropy >= 7.0) {
    return { level: 'HIGH', score: 20, description: 'High entropy - potential obfuscation' };
  }
  if (entropy >= 6.5) {
    return { level: 'MEDIUM', score: 10, description: 'Elevated entropy - review recommended' };
  }
  return { level: 'LOW', score: 0, description: 'Normal entropy' };
}
