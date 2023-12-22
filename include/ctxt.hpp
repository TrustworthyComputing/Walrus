#include "seal/seal.h"
#include <vector>

#ifndef _CTXT_HPP_
#define _CTXT_HPP_
class WalrusCtxt {
  public:

    // Create ciphertext object
    WalrusCtxt(seal::scheme_type scheme);

    // Encrypt single plaintext value (no batching)
    void WalrusEncryptSingle(seal::Encryptor& encryptor, uint64_t val);

    // Encrypt single float plaintext value (no batching)
    void WalrusEncryptSingleFloat(seal::Encryptor& encryptor, 
                                  seal::CKKSEncoder& encoder, double val, 
                                  double scale);

    // Encrypt plaintext vector (batching)
    void WalrusEncryptVector(seal::BatchEncoder& batch_encoder, seal::Encryptor& encryptor, 
                             std::vector<uint64_t>& vals);

    // Encrypt plaintext vector of floats (batching)
    void WalrusEncryptVectorFloat(seal::Encryptor& encryptor, 
                                  seal::CKKSEncoder& encoder, std::vector<double>& vals, 
                                  double scale);

    // Decrypt ciphertext using one slot (no batching)
    uint64_t WalrusDecryptSingle(seal::Decryptor& decryptor);

    // Decrypt encrypted float using one slot (no batching)
    double WalrusDecryptSingleFloat(seal::CKKSEncoder& encoder, 
                                    seal::Decryptor& decryptor);

    // Decrypt ciphertext slots (batching)
    std::vector<uint64_t> WalrusDecryptVector(seal::BatchEncoder& batch_encoder, 
                                              seal::Decryptor& decryptor);

    // Decrypt encrypted float vector (batching)
    std::vector<double> WalrusDecryptVectorFloat(seal::CKKSEncoder& encoder, 
                                                 seal::Decryptor& decryptor);

    seal::Ciphertext ctxt;
    seal::scheme_type scheme;
    int noise_budget;
    int mult_depth;
    int add_depth;
    double scale;
};
#endif /* _CTXT_HPP_ */