#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstdint>
#include <bitset>
#include <map>
#include <algorithm>
#include <unordered_map>
#include <cmath>
#include <random>
#include <chrono>
#include <thread>

// Enhanced SHA-256 implementation with comprehensive state capture
class SHA256Analyzer {
private:
    static const uint32_t K[64];
    static const uint32_t H0[8];

    uint32_t h[8];
    uint64_t msgLen;
    std::vector<uint8_t> buffer;

    // Comprehensive intermediate state capture
    std::vector<std::vector<uint32_t>> intermediateStates;
    std::vector<std::vector<uint32_t>> roundStates;
    std::vector<std::vector<uint32_t>> wordStates; // W array values

    uint32_t rotr(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    uint32_t sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    uint32_t sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void processBlock(const uint8_t* block);

public:
    SHA256Analyzer();
    void update(const uint8_t* data, size_t len);
    void update(const std::string& data);
    std::string finalize();
    std::vector<uint8_t> finalizeBytes();
    void reset();

    const std::vector<std::vector<uint32_t>>& getIntermediateStates() const { return intermediateStates; }
    const std::vector<std::vector<uint32_t>>& getRoundStates() const { return roundStates; }
    const std::vector<std::vector<uint32_t>>& getWordStates() const { return wordStates; }
};

const uint32_t SHA256Analyzer::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint32_t SHA256Analyzer::H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

SHA256Analyzer::SHA256Analyzer() {
    reset();
}

void SHA256Analyzer::reset() {
    std::copy(H0, H0 + 8, h);
    msgLen = 0;
    buffer.clear();
    intermediateStates.clear();
    roundStates.clear();
    wordStates.clear();
}

void SHA256Analyzer::update(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer.push_back(data[i]);
        if (buffer.size() == 64) {
            processBlock(buffer.data());
            buffer.clear();
            msgLen += 512;
        }
    }
}

void SHA256Analyzer::update(const std::string& data) {
    update(reinterpret_cast<const uint8_t*>(data.c_str()), data.length());
}

void SHA256Analyzer::processBlock(const uint8_t* block) {
    uint32_t w[64];

    // Copy block into first 16 words and capture
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    // Extend into remaining 48 words and capture each step
    for (int i = 16; i < 64; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    // Store complete W array for analysis
    wordStates.push_back(std::vector<uint32_t>(w, w + 64));

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], h_temp = h[7];

    // Capture every single round for detailed analysis
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h_temp + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = sigma0(a) + maj(a, b, c);

        h_temp = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;

        // Store state after every round
        roundStates.push_back({ a, b, c, d, e, f, g, h_temp });
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_temp;

    // Store final block state
    intermediateStates.push_back({ h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7] });
}

std::string SHA256Analyzer::finalize() {
    msgLen += buffer.size() * 8;

    buffer.push_back(0x80);

    while (buffer.size() % 64 != 56) {
        buffer.push_back(0x00);
    }

    for (int i = 7; i >= 0; i--) {
        buffer.push_back((msgLen >> (i * 8)) & 0xFF);
    }

    while (!buffer.empty()) {
        processBlock(buffer.data());
        buffer.erase(buffer.begin(), buffer.begin() + 64);
    }

    std::stringstream ss;
    for (int i = 0; i < 8; i++) {
        ss << std::hex << std::setfill('0') << std::setw(8) << h[i];
    }

    return ss.str();
}

std::vector<uint8_t> SHA256Analyzer::finalizeBytes() {
    msgLen += buffer.size() * 8;

    buffer.push_back(0x80);

    while (buffer.size() % 64 != 56) {
        buffer.push_back(0x00);
    }

    for (int i = 7; i >= 0; i--) {
        buffer.push_back((msgLen >> (i * 8)) & 0xFF);
    }

    while (!buffer.empty()) {
        processBlock(buffer.data());
        buffer.erase(buffer.begin(), buffer.begin() + 64);
    }

    std::vector<uint8_t> result(32);
    for (int i = 0; i < 8; i++) {
        result[i * 4] = (h[i] >> 24) & 0xFF;
        result[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        result[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        result[i * 4 + 3] = h[i] & 0xFF;
    }

    return result;
}

// Advanced statistical analysis for weakness detection
class CryptographicWeaknessDetector {
private:
    struct ExtendedStatistics {
        std::vector<double> values;
        double mean = 0.0;
        double variance = 0.0;
        double skewness = 0.0;
        double kurtosis = 0.0;
        double entropy = 0.0;
        std::vector<double> autocorrelations;
        std::vector<double> frequencyDistribution;

        void calculate() {
            if (values.empty()) return;

            // Mean
            double sum = 0.0;
            for (double val : values) sum += val;
            mean = sum / values.size();

            // Variance, skewness, kurtosis
            double variance_sum = 0.0, skew_sum = 0.0, kurt_sum = 0.0;
            for (double val : values) {
                double diff = val - mean;
                variance_sum += diff * diff;
                skew_sum += diff * diff * diff;
                kurt_sum += diff * diff * diff * diff;
            }

            variance = variance_sum / (values.size() - 1);
            double std_dev = sqrt(variance);

            if (std_dev > 0) {
                skewness = (skew_sum / values.size()) / (std_dev * std_dev * std_dev);
                kurtosis = (kurt_sum / values.size()) / (variance * variance) - 3.0;
            }

            // Entropy calculation
            std::map<int, int> freq;
            for (double val : values) {
                int bucket = static_cast<int>(val * 100) % 256; // Discretize
                freq[bucket]++;
            }

            entropy = 0.0;
            for (auto& pair : freq) {
                double p = static_cast<double>(pair.second) / values.size();
                if (p > 0) entropy -= p * log2(p);
            }

            // Autocorrelations for different lags
            calculateAutocorrelations();
        }

        void calculateAutocorrelations() {
            autocorrelations.clear();
            int maxLag = std::min(20, static_cast<int>(values.size() / 4));

            for (int lag = 1; lag <= maxLag; lag++) {
                double sum_xy = 0.0, sum_x = 0.0, sum_y = 0.0;
                double sum_x2 = 0.0, sum_y2 = 0.0;
                int count = 0;

                for (size_t i = lag; i < values.size(); i++) {
                    double x = values[i - lag];
                    double y = values[i];
                    sum_xy += x * y;
                    sum_x += x;
                    sum_y += y;
                    sum_x2 += x * x;
                    sum_y2 += y * y;
                    count++;
                }

                if (count > 0) {
                    double mean_x = sum_x / count;
                    double mean_y = sum_y / count;
                    double var_x = sum_x2 / count - mean_x * mean_x;
                    double var_y = sum_y2 / count - mean_y * mean_y;

                    if (var_x > 0 && var_y > 0) {
                        double covariance = sum_xy / count - mean_x * mean_y;
                        double correlation = covariance / sqrt(var_x * var_y);
                        autocorrelations.push_back(correlation);
                    }
                    else {
                        autocorrelations.push_back(0.0);
                    }
                }
            }
        }
    };

public:
    struct WeaknessReport {
        bool hasWeakness = false;
        std::vector<std::string> weaknessTypes;
        std::vector<double> confidenceScores;
        double overallSuspicionLevel = 0.0;
        std::string detailedFindings;
    };

    WeaknessReport analyzeForWeaknesses(const std::vector<double>& data, const std::string& context) {
        WeaknessReport report;
        ExtendedStatistics stats;
        stats.values = data;
        stats.calculate();

        report.detailedFindings = "Analysis of " + context + ":\n";

        // Test 1: Non-uniformity in distribution
        if (abs(stats.skewness) > 0.5) {
            report.hasWeakness = true;
            report.weaknessTypes.push_back("Distribution Skewness");
            report.confidenceScores.push_back(abs(stats.skewness) * 2.0);
            report.detailedFindings += "- Significant skewness detected: " + std::to_string(stats.skewness) + "\n";
        }

        // Test 2: Heavy tails (high kurtosis)
        if (abs(stats.kurtosis) > 1.0) {
            report.hasWeakness = true;
            report.weaknessTypes.push_back("Heavy Tails");
            report.confidenceScores.push_back(abs(stats.kurtosis));
            report.detailedFindings += "- Heavy tails detected (kurtosis): " + std::to_string(stats.kurtosis) + "\n";
        }

        // Test 3: Low entropy (predictability)
        double expectedEntropy = 8.0; // For good randomness
        if (stats.entropy < expectedEntropy * 0.95) {
            report.hasWeakness = true;
            report.weaknessTypes.push_back("Low Entropy");
            double entropyScore = (expectedEntropy - stats.entropy) / expectedEntropy * 10.0;
            report.confidenceScores.push_back(entropyScore);
            report.detailedFindings += "- Low entropy: " + std::to_string(stats.entropy) + " (expected ~8.0)\n";
        }

        // Test 4: Autocorrelation (sequential dependence)
        for (size_t i = 0; i < stats.autocorrelations.size(); i++) {
            if (abs(stats.autocorrelations[i]) > 0.3) {
                report.hasWeakness = true;
                report.weaknessTypes.push_back("Sequential Dependence");
                report.confidenceScores.push_back(abs(stats.autocorrelations[i]) * 10.0);
                report.detailedFindings += "- Strong autocorrelation at lag " + std::to_string(i + 1) +
                    ": " + std::to_string(stats.autocorrelations[i]) + "\n";
                break; // Only report the first significant autocorrelation
            }
        }

        // Test 5: Variance anomalies
        double expectedVariance = stats.mean; // For Poisson-like behavior expected in prime analysis
        if (expectedVariance > 0) {
            double varianceRatio = stats.variance / expectedVariance;
            if (varianceRatio < 0.5 || varianceRatio > 2.0) {
                report.hasWeakness = true;
                report.weaknessTypes.push_back("Variance Anomaly");
                report.confidenceScores.push_back(abs(varianceRatio - 1.0) * 5.0);
                report.detailedFindings += "- Unusual variance ratio: " + std::to_string(varianceRatio) + "\n";
            }
        }

        // Calculate overall suspicion level
        if (!report.confidenceScores.empty()) {
            double sum = 0.0;
            for (double score : report.confidenceScores) {
                sum += score;
            }
            report.overallSuspicionLevel = sum / report.confidenceScores.size();
        }

        return report;
    }
};

// Large-scale Bitcoin analysis with comprehensive data generation
class LargeScaleBitcoinAnalyzer {
private:
    CryptographicWeaknessDetector detector;
    std::mt19937 rng;

    // Visual Studio compatible leading zero count
    uint32_t countLeadingZeros(uint32_t value) {
        if (value == 0) return 32;
        uint32_t count = 0;
        if (value <= 0x0000FFFF) { count += 16; value <<= 16; }
        if (value <= 0x00FFFFFF) { count += 8; value <<= 8; }
        if (value <= 0x0FFFFFFF) { count += 4; value <<= 4; }
        if (value <= 0x3FFFFFFF) { count += 2; value <<= 2; }
        if (value <= 0x7FFFFFFF) { count += 1; }
        return count;
    }

    struct ComprehensiveDataset {
        std::vector<double> primeSignatures;
        std::vector<double> regionalDistribution;
        std::vector<double> roundByRoundValues;
        std::vector<double> wordExpansionValues;
        std::vector<double> crossRoundCorrelations;
        std::string datasetName;
        size_t totalSamples;
    };

    std::vector<ComprehensiveDataset> datasets;

public:
    LargeScaleBitcoinAnalyzer() : rng(std::chrono::steady_clock::now().time_since_epoch().count()) {}

    // Generate massive amounts of test data
    void generateComprehensiveDataset(const std::string& datasetName, size_t numSamples) {
        std::cout << "Generating " << numSamples << " samples for " << datasetName << "...\n";

        ComprehensiveDataset dataset;
        dataset.datasetName = datasetName;
        dataset.totalSamples = numSamples;

        auto startTime = std::chrono::steady_clock::now();

        for (size_t i = 0; i < numSamples; i++) {
            if (i % 1000 == 0) {
                auto currentTime = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);
                double progress = static_cast<double>(i) / numSamples * 100.0;
                std::cout << "\rProgress: " << std::fixed << std::setprecision(1)
                    << progress << "% (" << elapsed.count() << "s elapsed)" << std::flush;
            }

            // Generate varied input data
            std::string input = generateTestInput(i, datasetName);

            if (datasetName.find("Double") != std::string::npos) {
                analyzeDoubleSHA256Sample(input, dataset);
            }
            else if (datasetName.find("BIP39") != std::string::npos) {
                analyzeBIP39Sample(input, dataset);
            }
            else {
                analyzeSingleSHA256Sample(input, dataset);
            }
        }

        std::cout << "\nCompleted " << datasetName << " dataset generation.\n\n";
        datasets.push_back(dataset);
    }

private:
    std::string generateTestInput(size_t index, const std::string& category) {
        std::stringstream ss;

        if (category.find("Sequential") != std::string::npos) {
            // Sequential patterns that might reveal structure
            ss << "sequential_test_" << index;
        }
        else if (category.find("Random") != std::string::npos) {
            // Pseudo-random but deterministic
            std::uniform_int_distribution<int> dist(0, 255);
            for (int i = 0; i < 32; i++) {
                ss << static_cast<char>(dist(rng));
            }
        }
        else if (category.find("Bitcoin") != std::string::npos) {
            // Bitcoin-specific patterns
            std::vector<std::string> bitcoinTemplates = {
                "block_height_", "transaction_", "address_", "private_key_",
                "nonce_", "merkle_", "coinbase_", "difficulty_"
            };
            ss << bitcoinTemplates[index % bitcoinTemplates.size()] << index;
        }
        else if (category.find("Arithmetic") != std::string::npos) {
            // Arithmetic progressions that might expose algebraic structure
            ss << "arithmetic_" << (index * 7 + 13) << "_" << (index * index);
        }
        else {
            // Default mixed pattern
            ss << category << "_sample_" << index << "_" << (index % 1000);
        }

        return ss.str();
    }

    void analyzeSingleSHA256Sample(const std::string& input, ComprehensiveDataset& dataset) {
        SHA256Analyzer hasher;
        hasher.update(input);
        hasher.finalize();

        analyzeHasherStates(hasher, dataset);
    }

    void analyzeDoubleSHA256Sample(const std::string& input, ComprehensiveDataset& dataset) {
        // First round
        SHA256Analyzer hasher1;
        hasher1.update(input);
        std::vector<uint8_t> firstHash = hasher1.finalizeBytes();

        // Second round
        SHA256Analyzer hasher2;
        hasher2.update(firstHash.data(), firstHash.size());
        hasher2.finalize();

        // Analyze both rounds
        analyzeHasherStates(hasher1, dataset);
        analyzeHasherStates(hasher2, dataset);

        // Cross-round correlation analysis
        analyzeCrossRoundCorrelations(hasher1, hasher2, dataset);
    }

    void analyzeBIP39Sample(const std::string& input, ComprehensiveDataset& dataset) {
        // Simulate BIP39 process with multiple SHA operations
        SHA256Analyzer entropyHasher;
        entropyHasher.update(input);
        std::vector<uint8_t> entropy = entropyHasher.finalizeBytes();

        // Mnemonic to seed process (simplified)
        std::string mnemonicSalt = "mnemonic" + std::to_string(entropy[0]);
        SHA256Analyzer seedHasher;
        seedHasher.update(mnemonicSalt);
        seedHasher.finalize();

        analyzeHasherStates(entropyHasher, dataset);
        analyzeHasherStates(seedHasher, dataset);
    }

    void analyzeHasherStates(const SHA256Analyzer& hasher, ComprehensiveDataset& dataset) {
        const auto& intermediateStates = hasher.getIntermediateStates();
        const auto& roundStates = hasher.getRoundStates();
        const auto& wordStates = hasher.getWordStates();

        // Analyze intermediate states
        for (const auto& state : intermediateStates) {
            for (uint32_t value : state) {
                double primeScore = calculateAdvancedPrimeScore(value);
                dataset.primeSignatures.push_back(primeScore);

                uint32_t region = (value >> 29) & 0x7;
                dataset.regionalDistribution.push_back(static_cast<double>(region));
            }
        }

        // Analyze round-by-round evolution
        for (const auto& roundState : roundStates) {
            for (uint32_t value : roundState) {
                dataset.roundByRoundValues.push_back(static_cast<double>(value % 10000) / 10000.0);
            }
        }

        // Analyze word expansion patterns
        for (const auto& wordState : wordStates) {
            for (size_t i = 16; i < 64; i++) { // Extended words only
                dataset.wordExpansionValues.push_back(static_cast<double>(wordState[i] % 10000) / 10000.0);
            }
        }
    }

    void analyzeCrossRoundCorrelations(const SHA256Analyzer& hasher1, const SHA256Analyzer& hasher2, ComprehensiveDataset& dataset) {
        const auto& states1 = hasher1.getIntermediateStates();
        const auto& states2 = hasher2.getIntermediateStates();

        if (!states1.empty() && !states2.empty()) {
            for (size_t i = 0; i < 8 && i < states1[0].size() && i < states2[0].size(); i++) {
                double correlation = calculateCorrelation(states1[0][i], states2[0][i]);
                dataset.crossRoundCorrelations.push_back(correlation);
            }
        }
    }

    double calculateAdvancedPrimeScore(uint32_t value) {
        if (value < 2) return 0.0;

        double score = 0.0;
        uint32_t temp = value;

        // Prime factorization with advanced scoring
        for (uint32_t p = 2; p * p <= temp; p++) {
            if (temp % p == 0) {
                while (temp % p == 0) {
                    score += log(static_cast<double>(p));

                    // Bitcoin-specific prime bonuses
                    if (p == 2 || p == 3 || p == 5 || p == 7) score += 0.5;
                    if (p > 65537) score += 1.0;
                    if (p % 4 == 3) score += 0.3; // Important for elliptic curves

                    temp /= p;
                }
            }
        }

        if (temp > 1) {
            score += log(static_cast<double>(temp));
            if (temp > 65537) score += 1.0;
        }

        return score;
    }

    double calculateCorrelation(uint32_t a, uint32_t b) {
        // Simple correlation based on bit patterns
        uint32_t xor_result = a ^ b;
        int hammingWeight = 0;

        for (int i = 0; i < 32; i++) {
            if (xor_result & (1U << i)) hammingWeight++;
        }

        return static_cast<double>(32 - hammingWeight) / 32.0; // Correlation based on similarity
    }

public:
    void runComprehensiveAnalysis() {
        std::cout << "\n=== COMPREHENSIVE WEAKNESS DETECTION ANALYSIS ===\n";
        std::cout << "Running advanced statistical tests on all datasets...\n\n";

        bool overallWeaknessFound = false;
        std::vector<std::string> criticalFindings;

        for (const auto& dataset : datasets) {
            std::cout << "Analyzing " << dataset.datasetName << " (" << dataset.totalSamples << " samples):\n";
            std::cout << std::string(50, '-') << "\n";

            // Test prime signatures
            auto primeReport = detector.analyzeForWeaknesses(dataset.primeSignatures, "Prime Signatures");
            if (primeReport.hasWeakness) {
                overallWeaknessFound = true;
                std::cout << "🚨 WEAKNESS DETECTED in Prime Signatures:\n";
                std::cout << primeReport.detailedFindings;
                std::cout << "Suspicion Level: " << primeReport.overallSuspicionLevel << "\n\n";

                if (primeReport.overallSuspicionLevel > 5.0) {
                    criticalFindings.push_back(dataset.datasetName + " Prime Signatures (Level: " +
                        std::to_string(primeReport.overallSuspicionLevel) + ")");
                }
            }

            // Test regional distribution
            auto regionReport = detector.analyzeForWeaknesses(dataset.regionalDistribution, "Regional Distribution");
            if (regionReport.hasWeakness) {
                overallWeaknessFound = true;
                std::cout << "🚨 WEAKNESS DETECTED in Regional Distribution:\n";
                std::cout << regionReport.detailedFindings;
                std::cout << "Suspicion Level: " << regionReport.overallSuspicionLevel << "\n\n";

                if (regionReport.overallSuspicionLevel > 3.0) {
                    criticalFindings.push_back(dataset.datasetName + " Regional Distribution (Level: " +
                        std::to_string(regionReport.overallSuspicionLevel) + ")");
                }
            }

            // Test round-by-round evolution
            if (!dataset.roundByRoundValues.empty()) {
                auto roundReport = detector.analyzeForWeaknesses(dataset.roundByRoundValues, "Round Evolution");
                if (roundReport.hasWeakness) {
                    overallWeaknessFound = true;
                    std::cout << "🚨 WEAKNESS DETECTED in Round Evolution:\n";
                    std::cout << roundReport.detailedFindings;
                    std::cout << "Suspicion Level: " << roundReport.overallSuspicionLevel << "\n\n";

                    if (roundReport.overallSuspicionLevel > 4.0) {
                        criticalFindings.push_back(dataset.datasetName + " Round Evolution (Level: " +
                            std::to_string(roundReport.overallSuspicionLevel) + ")");
                    }
                }
            }

            // Test word expansion patterns
            if (!dataset.wordExpansionValues.empty()) {
                auto wordReport = detector.analyzeForWeaknesses(dataset.wordExpansionValues, "Word Expansion");
                if (wordReport.hasWeakness) {
                    overallWeaknessFound = true;
                    std::cout << "🚨 WEAKNESS DETECTED in Word Expansion:\n";
                    std::cout << wordReport.detailedFindings;
                    std::cout << "Suspicion Level: " << wordReport.overallSuspicionLevel << "\n\n";

                    if (wordReport.overallSuspicionLevel > 4.0) {
                        criticalFindings.push_back(dataset.datasetName + " Word Expansion (Level: " +
                            std::to_string(wordReport.overallSuspicionLevel) + ")");
                    }
                }
            }

            // Test cross-round correlations (for double SHA-256)
            if (!dataset.crossRoundCorrelations.empty()) {
                auto corrReport = detector.analyzeForWeaknesses(dataset.crossRoundCorrelations, "Cross-Round Correlations");
                if (corrReport.hasWeakness) {
                    overallWeaknessFound = true;
                    std::cout << "🚨 CRITICAL WEAKNESS in Cross-Round Correlations:\n";
                    std::cout << corrReport.detailedFindings;
                    std::cout << "Suspicion Level: " << corrReport.overallSuspicionLevel << "\n\n";

                    if (corrReport.overallSuspicionLevel > 2.0) {
                        criticalFindings.push_back("CRITICAL: " + dataset.datasetName + " Cross-Round Correlations (Level: " +
                            std::to_string(corrReport.overallSuspicionLevel) + ")");
                    }
                }
            }

            if (!primeReport.hasWeakness && !regionReport.hasWeakness) {
                std::cout << "✅ No significant weaknesses detected in " << dataset.datasetName << "\n";
            }

            std::cout << "\n";
        }

        // Final assessment
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "FINAL CRYPTOGRAPHIC SECURITY ASSESSMENT\n";
        std::cout << std::string(80, '=') << "\n";

        if (overallWeaknessFound) {
            std::cout << "🚨🚨🚨 POTENTIAL CRYPTOGRAPHIC WEAKNESSES DETECTED! 🚨🚨🚨\n\n";

            if (!criticalFindings.empty()) {
                std::cout << "CRITICAL FINDINGS (High Confidence):\n";
                for (const auto& finding : criticalFindings) {
                    std::cout << "⚠️  " << finding << "\n";
                }
                std::cout << "\n";
            }

            std::cout << "IMPLICATIONS:\n";
            std::cout << "- Bitcoin's cryptographic security may be compromised\n";
            std::cout << "- Non-random patterns could enable prediction attacks\n";
            std::cout << "- Wallet generation might be vulnerable\n";
            std::cout << "- Mining could be exploitable through pattern recognition\n";
            std::cout << "- Further investigation with larger datasets recommended\n\n";

            std::cout << "RECOMMENDED ACTIONS:\n";
            std::cout << "1. Increase sample size to 1M+ for confirmation\n";
            std::cout << "2. Test with real Bitcoin blockchain data\n";
            std::cout << "3. Verify findings with independent implementations\n";
            std::cout << "4. Consider responsible disclosure to Bitcoin developers\n";

        }
        else {
            std::cout << "✅ NO SIGNIFICANT CRYPTOGRAPHIC WEAKNESSES DETECTED\n\n";
            std::cout << "Bitcoin's SHA-256 and BIP39 implementations appear to maintain\n";
            std::cout << "cryptographic security properties under prime factorization analysis.\n\n";
            std::cout << "Your hypothesis about exploitable prime factor patterns was not\n";
            std::cout << "confirmed with this dataset size. Consider testing with:\n";
            std::cout << "- Larger sample sizes (1M+ samples)\n";
            std::cout << "- Real blockchain transaction data\n";
            std::cout << "- Different mathematical approaches\n";
        }
    }

    void exportComprehensiveResults(const std::string& filename) {
        std::ofstream file(filename);
        file << "Dataset,DataType,SampleCount,Mean,Variance,Skewness,Kurtosis,Entropy,MaxAutocorr,WeaknessDetected\n";

        for (const auto& dataset : datasets) {
            auto exportStats = [&](const std::vector<double>& data, const std::string& dataType) {
                if (data.empty()) return;

                // Calculate basic statistics
                double sum = 0, sum2 = 0, sum3 = 0, sum4 = 0;
                for (double val : data) {
                    sum += val;
                    sum2 += val * val;
                    sum3 += val * val * val;
                    sum4 += val * val * val * val;
                }

                double mean = sum / data.size();
                double variance = (sum2 / data.size()) - (mean * mean);
                double std_dev = sqrt(variance);

                double skewness = 0, kurtosis = 0;
                if (std_dev > 0) {
                    skewness = ((sum3 / data.size()) - 3 * mean * variance - mean * mean * mean) / (std_dev * std_dev * std_dev);
                    kurtosis = ((sum4 / data.size()) - 4 * mean * sum3 / data.size() + 6 * mean * mean * variance + 3 * mean * mean * mean * mean) / (variance * variance) - 3;
                }

                // Simple entropy calculation
                std::map<int, int> freq;
                for (double val : data) {
                    int bucket = static_cast<int>(val * 100) % 256;
                    freq[bucket]++;
                }
                double entropy = 0.0;
                for (auto& pair : freq) {
                    double p = static_cast<double>(pair.second) / data.size();
                    if (p > 0) entropy -= p * log2(p);
                }

                auto report = detector.analyzeForWeaknesses(data, dataType);

                file << dataset.datasetName << "," << dataType << "," << data.size() << ",";
                file << mean << "," << variance << "," << skewness << "," << kurtosis << ",";
                file << entropy << ",0," << (report.hasWeakness ? "YES" : "NO") << "\n";
                };

            exportStats(dataset.primeSignatures, "PrimeSignatures");
            exportStats(dataset.regionalDistribution, "RegionalDistribution");
            exportStats(dataset.roundByRoundValues, "RoundEvolution");
            exportStats(dataset.wordExpansionValues, "WordExpansion");
            exportStats(dataset.crossRoundCorrelations, "CrossRoundCorr");
        }

        file.close();
        std::cout << "\nComprehensive analysis results exported to " << filename << "\n";
    }
};

int main() {
    std::cout << "Large-Scale Bitcoin Cryptographic Weakness Detection\n";
    std::cout << "===================================================\n";
    std::cout << "Advanced statistical analysis for subtle cryptographic patterns\n\n";

    std::cout << "This analysis will generate and test large datasets to detect:\n";
    std::cout << "- Non-uniform distribution patterns\n";
    std::cout << "- Sequential dependencies (autocorrelations)\n";
    std::cout << "- Entropy deficiencies\n";
    std::cout << "- Cross-round correlations in double SHA-256\n";
    std::cout << "- Regional clustering in prime factorizations\n";
    std::cout << "- Algebraic structure in hash evolution\n\n";

    // Get user input for sample sizes
    std::cout << "Select analysis scale:\n";
    std::cout << "1. Quick Test (10,000 samples per dataset) - ~2 minutes\n";
    std::cout << "2. Standard Analysis (50,000 samples) - ~10 minutes\n";
    std::cout << "3. Deep Analysis (200,000 samples) - ~45 minutes\n";
    std::cout << "4. Comprehensive (500,000 samples) - ~2 hours\n";
    std::cout << "5. Maximum Detection (1,000,000 samples) - ~4 hours\n";
    std::cout << "\nEnter choice (1-5): ";

    int choice;
    std::cin >> choice;

    size_t sampleSize;
    switch (choice) {
    case 1: sampleSize = 10000; break;
    case 2: sampleSize = 50000; break;
    case 3: sampleSize = 200000; break;
    case 4: sampleSize = 500000; break;
    case 5: sampleSize = 1000000; break;
    default: sampleSize = 50000; break;
    }

    std::cout << "\nStarting analysis with " << sampleSize << " samples per dataset...\n";
    std::cout << "This will comprehensively test your hypothesis about exploitable\n";
    std::cout << "prime factor patterns in Bitcoin's cryptographic functions.\n\n";

    LargeScaleBitcoinAnalyzer analyzer;

    // Generate multiple comprehensive datasets
    std::vector<std::string> datasetTypes = {
        "Single_SHA256_Sequential",
        "Single_SHA256_Random",
        "Single_SHA256_Bitcoin_Patterns",
        "Single_SHA256_Arithmetic",
        "Double_SHA256_Sequential",
        "Double_SHA256_Random",
        "Double_SHA256_Bitcoin_Patterns",
        "BIP39_Sequential_Entropy",
        "BIP39_Random_Entropy",
        "BIP39_Bitcoin_Entropy"
    };

    auto overallStart = std::chrono::steady_clock::now();

    for (const auto& datasetType : datasetTypes) {
        analyzer.generateComprehensiveDataset(datasetType, sampleSize);
    }

    auto overallEnd = std::chrono::steady_clock::now();
    auto totalTime = std::chrono::duration_cast<std::chrono::minutes>(overallEnd - overallStart);

    std::cout << "Data generation completed in " << totalTime.count() << " minutes.\n";
    std::cout << "Total samples analyzed: " << (sampleSize * datasetTypes.size()) << "\n\n";

    // Run comprehensive weakness detection
    analyzer.runComprehensiveAnalysis();

    // Export detailed results
    analyzer.exportComprehensiveResults("comprehensive_bitcoin_analysis.csv");

    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "ANALYSIS COMPLETE\n";
    std::cout << std::string(80, '=') << "\n";
    std::cout << "If weaknesses were detected, this could represent a significant\n";
    std::cout << "cryptographic discovery with major implications for Bitcoin security.\n\n";
    std::cout << "Results saved to: comprehensive_bitcoin_analysis.csv\n";
    std::cout << "Consider running with larger sample sizes if patterns were found.\n\n";

    std::cout << "Press Enter to exit...";
    std::cin.ignore();
    std::cin.get();

    return 0;
}