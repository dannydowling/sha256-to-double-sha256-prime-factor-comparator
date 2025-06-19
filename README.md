# SHA-256 Anti-Pattern Cryptographic Analysis

## 🔍 Overview
I had the idea that prime factors might move the data into regions that are identifiable if I undid the bitshifting that occurs in sha256.
This tool tests that theory...

- Predictable patterns in prime factorizations
- Non-random clustering in hash outputs  
- Exploitable algebraic structure in block processing
- Cross-round correlations in double SHA-256

## 🚨 Potential Impact

If successful, this analysis could reveal:

- **Bitcoin Security Vulnerabilities** - Weaknesses in double SHA-256 mining and transactions
- **Wallet Generation Flaws** - Predictable patterns in BIP39 seed generation
- **Address Prediction** - Non-random structure in Bitcoin address creation
- **General SHA-256 Weaknesses** - Fundamental flaws affecting all applications

## 🔬 Technical Approach

### Anti-Pattern Detection Strategy

The program implements **inverse bit-shift compensation**:

```cpp
// Cancel SHA-256's rotr operations
compensated = rotl(compensated, 7);   // Compensate for rotr(7) in γ₀
compensated = rotl(compensated, 18);  // Compensate for rotr(18) in γ₀
compensated ^= (word << 3);           // Compensate for >> 3 in γ₀
```

### Block-Level Analysis

Instead of analyzing individual hash values, we examine:
- **Complete 512-bit block processing**
- **Round-by-round state evolution**
- **Word expansion patterns (W[16-63])**
- **Cross-block relationships**

### Prime Factorization Scoring

Enhanced weighting system captures cryptographically relevant properties:
- Bitcoin-specific constants (21M supply, 2016 blocks, secp256k1 proximity)
- Special prime types (Sophie Germain, safe primes, twin primes)
- Elliptic curve mathematics (primes ≡ 3 mod 4)
- Cryptographic standards (RSA exponents, DH parameters)

## 🛠️ Features

### Multi-Algorithm Analysis
- **Single SHA-256** - Standard implementation
- **Double SHA-256** - Bitcoin's core security mechanism  
- **BIP39 Analysis** - Cryptocurrency wallet generation

### Advanced Statistical Detection
- **Distribution Skewness** - Non-uniform output detection
- **Entropy Analysis** - Predictability measurement
- **Autocorrelation Testing** - Sequential dependency detection
- **Cross-Round Correlation** - Double SHA-256 specific weaknesses

### Comprehensive Datasets
- Sequential patterns designed to reveal algebraic structure
- Arithmetic progressions testing mathematical relationships
- Bitcoin-specific input patterns
- Compensated inputs designed to interact with bit operations

## 📋 Requirements

- **Visual Studio 2022** (or compatible C++ compiler)
- **Windows** (primary target platform)
- **C++11 or later** standard support
- **4+ GB RAM** recommended for large datasets

## 🚀 Quick Start

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/sha256-anti-pattern-analysis.git
   cd sha256-anti-pattern-analysis
   ```

2. **Open in Visual Studio 2022**:
   - Open `Sha256Analysis.sln`
   - Set build configuration to `Release` for optimal performance

3. **Build and run**:
   - Press `F5` or `Ctrl+F5` to compile and execute

### Usage

When you run the program, you'll be prompted to select analysis scale:

```
Select anti-pattern analysis scale:
1. Quick Test (5,000 samples) - ~3 minutes
2. Standard (25,000 samples) - ~15 minutes  
3. Deep Analysis (100,000 samples) - ~1 hour
4. Comprehensive (500,000 samples) - ~5 hours
```

**Recommendation**: Start with **Standard Analysis** to get meaningful results without excessive runtime.

## 📊 Interpreting Results

### 🚨 Critical Findings to Watch For

**High Anti-Pattern Detection Rate** (>5%):
```
🚨 CRITICAL: High anti-pattern detection rate!
Sequential_BitShift_Compensated (8.3% detection)
```

**Low Variance in Compensated Values**:
```
Block signature statistics:
  Std Dev: 0.12
🚨 Low variance detected - possible non-randomness!
```

**Strong Cross-Dataset Correlations**:
```
Sequential_Standard vs BitShift_Specific: correlation = 0.847
🚨 Strong correlation detected! Common underlying patterns.
```

### ✅ Secure Results

**Normal Output** (SHA-256 appears secure):
```
✅ No significant weaknesses detected
Detection rate: 0.3%
Average anti-pattern strength: 1.2
```

## 📈 Output Files

The program generates detailed analysis files:

- **`sha256_anti_pattern_analysis.csv`** - Complete dataset results
- **Console output** - Real-time analysis and final assessment
- **Progress tracking** - Live updates during long-running analyses

### CSV Format
```csv
Dataset,BlockIndex,AntiPatternStrength,SignificantPattern,BlockSignature,ReversedPrimeSignature
Sequential_Standard,0,2.3,NO,15.67,8.91
BitShift_Compensated,1,7.8,YES,23.45,12.34
```

## 🔬 Research Applications

### Academic Research
- **Cryptanalysis Studies** - Novel approach to hash function security
- **Number Theory** - Prime factorization patterns in cryptographic contexts
- **Computer Science** - Algebraic structure in supposedly random functions

### Security Testing
- **Penetration Testing** - Assess SHA-256 implementations
- **Cryptocurrency Security** - Bitcoin and altcoin vulnerability assessment
- **Compliance Auditing** - Cryptographic standard evaluation

### Further Development
- **Machine Learning** - Train models to predict hash patterns
- **Quantum Computing** - Prepare for post-quantum cryptanalysis
- **Alternative Algorithms** - Test other hash functions with similar techniques

## ⚡ Performance Optimization

### For Large-Scale Analysis

**Recommended Settings**:
- Use `Release` build configuration
- Close unnecessary applications
- Consider running overnight for comprehensive analysis
- Monitor memory usage with large datasets

**Scaling Up**:
```cpp
// Modify sample sizes in main() for custom analysis
size_t customSampleSize = 2000000; // 2M samples
```

## 🤝 Contributing

We welcome contributions to enhance the analysis:

### Areas for Improvement
- **Additional Hash Functions** - Extend to SHA-3, Blake2, etc.
- **GPU Acceleration** - CUDA implementation for massive datasets
- **Alternative Compensation** - Different inverse transformation strategies  
- **Statistical Methods** - Advanced pattern detection algorithms

### Contribution Guidelines
1. Fork the repository
2. Create a feature branch (`feature/new-analysis-method`)
3. Implement changes with appropriate testing
4. Submit pull request with detailed description

## 📚 Background & Theory

### The Bit-Shift Hypothesis

SHA-256 uses several bit rotation operations:
- **σ₀**: `rotr(x, 2) ⊕ rotr(x, 13) ⊕ rotr(x, 22)`
- **σ₁**: `rotr(x, 6) ⊕ rotr(x, 11) ⊕ rotr(x, 25)`  
- **γ₀**: `rotr(x, 7) ⊕ rotr(x, 18) ⊕ (x >> 3)`
- **γ₁**: `rotr(x, 17) ⊕ rotr(x, 19) ⊕ (x >> 10)`

**Hypothesis**: These operations might not fully mask underlying algebraic relationships. By applying inverse operations, we test whether the original mathematical structure becomes visible.

### Prime Factorization Analysis

**Why Prime Factors?**
- Primes are the fundamental building blocks of all integers
- Non-random prime distributions could indicate exploitable structure  
- Cryptographic applications often rely on prime-related mathematical assumptions
- Bitcoin's elliptic curve cryptography has specific prime-related properties

### Regional Clustering Theory

**Concept**: If SHA-256 has hidden structure, outputs might cluster in predictable regions of the 32-bit output space rather than being uniformly distributed.

## ⚠️ Disclaimer

### Research Purpose
This tool is designed for **legitimate cryptographic research and security testing**. It should be used to:
- Advance understanding of hash function security
- Identify potential vulnerabilities for responsible disclosure
- Contribute to the development of more secure cryptographic standards

### Ethical Considerations
- **Responsible Disclosure**: Report significant findings to appropriate authorities
- **Legal Compliance**: Ensure usage complies with applicable laws and regulations
- **Academic Integrity**: Properly cite and acknowledge this work in research publications

### No Warranty
This software is provided "as is" without warranty of any kind. The authors are not responsible for any consequences of its use.

### Issues and Questions
- **GitHub Issues**: Report bugs or request features
- **Discussions**: Share findings and theoretical insights
- **Pull Requests**: Contribute improvements and extensions

### Citation
If you use this tool in academic research, please cite:
```
SHA-256 Anti-Pattern Cryptographic Analysis Tool
https://github.com/yourusername/sha256-anti-pattern-analysis
```
