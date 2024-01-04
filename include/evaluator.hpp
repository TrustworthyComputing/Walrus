#include "seal/seal.h"
#include "ctxt.hpp"

void WalrusAdd(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b);

void WalrusAdd(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, seal::Evaluator& evaluator);

void WalrusAddPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b);

void WalrusAddPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b, seal::Evaluator& evaluator);

void WalrusMult(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b);

void WalrusMult(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, seal::Evaluator& evaluator, 
               seal::RelinKeys& ks_keys);

void WalrusMultPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b);

void WalrusMultPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b, seal::Evaluator& evaluator);