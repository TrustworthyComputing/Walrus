#include "seal/seal.h"
#include "ctxt.hpp"

void WalrusAdd(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, seal::Evaluator& evaluator, 
               bool first_pass=false);

void WalrusAddPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b, seal::Evaluator& evaluator, 
               bool first_pass=false);

void WalrusMult(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, seal::Evaluator& evaluator, 
               seal::RelinKeys& ks_keys, bool first_pass=false);

void WalrusMultPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b, seal::Evaluator& evaluator, 
               bool first_pass=false);