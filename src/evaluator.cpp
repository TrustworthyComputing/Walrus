#include "evaluator.hpp"

using namespace std;
using namespace seal;

void WalrusAdd(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, Evaluator& evaluator, 
               bool first_pass) {
  evaluator.add(ct_a.ctxt, ct_b.ctxt, ct_out.ctxt);
  if (first_pass) {
    ct_out.add_depth = (ct_a.add_depth > ct_b.add_depth) ? ct_a.add_depth + 1 : ct_b.add_depth + 1;
  }
}

void WalrusAddPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b, seal::Evaluator& evaluator, 
               bool first_pass) {
  evaluator.add_plain(ct_a.ctxt, pt_b, ct_out.ctxt);
  if (first_pass) {
    ct_out.add_depth = ct_a.add_depth;
  }
}

void WalrusMult(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, Evaluator& evaluator, 
               RelinKeys& ks_keys, bool first_pass) {
  evaluator.multiply(ct_a.ctxt, ct_b.ctxt, ct_out.ctxt);
  evaluator.relinearize_inplace(ct_out.ctxt, ks_keys);
  if (ct_a.scheme == scheme_type::ckks) {
    evaluator.rescale_to_next_inplace(ct_out.ctxt);
    ct_out.ctxt.scale() = ct_out.scale;
  } else {
    evaluator.mod_switch_to_next_inplace(ct_out.ctxt);
  }
  if (first_pass) {
    ct_out.mult_depth = (ct_a.mult_depth > ct_b.mult_depth) ? ct_a.mult_depth + 1 : ct_b.mult_depth + 1;
  }
}

void WalrusMultPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const seal::Plaintext& pt_b, seal::Evaluator& evaluator, 
               bool first_pass) {
  evaluator.multiply_plain(ct_a.ctxt, pt_b, ct_out.ctxt);
  if (first_pass) {
    ct_out.mult_depth = ct_a.mult_depth + 1;
  }
}
