#include "evaluator.hpp"

using namespace std;
using namespace seal;

void WalrusAdd(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b) {
  ct_out.add_depth = (ct_a.add_depth > ct_b.add_depth) ? ct_a.add_depth + 1 : ct_b.add_depth + 1;
  ct_out.mult_depth = (ct_a.mult_depth > ct_b.mult_depth) ? ct_a.mult_depth : ct_b.mult_depth;
}

void WalrusAdd(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, Evaluator& evaluator) {
  evaluator.add(ct_a.ctxt, ct_b.ctxt, ct_out.ctxt);
}

void WalrusAddPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                    const Plaintext& pt_b) {
  ct_out.add_depth = ct_a.add_depth;
  ct_out.mult_depth = ct_a.mult_depth;
}

void WalrusAddPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                    const Plaintext& pt_b, Evaluator& evaluator) {
  evaluator.add_plain(ct_a.ctxt, pt_b, ct_out.ctxt);
}

void WalrusSub(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b) {
  ct_out.add_depth = (ct_a.add_depth > ct_b.add_depth) ? ct_a.add_depth + 1 : ct_b.add_depth + 1;
  ct_out.mult_depth = (ct_a.mult_depth > ct_b.mult_depth) ? ct_a.mult_depth : ct_b.mult_depth;
}

void WalrusSub(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
               const WalrusCtxt& ct_b, Evaluator& evaluator) {
  evaluator.sub(ct_a.ctxt, ct_b.ctxt, ct_out.ctxt);
}

void WalrusSubPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                    const Plaintext& pt_b) {
  ct_out.add_depth = ct_a.add_depth;
  ct_out.mult_depth = ct_a.mult_depth;
}

void WalrusSubPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                    const Plaintext& pt_b, Evaluator& evaluator) {
  evaluator.sub_plain(ct_a.ctxt, pt_b, ct_out.ctxt);
}

void WalrusMult(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                const WalrusCtxt& ct_b) {
  ct_out.add_depth = (ct_a.add_depth > ct_b.add_depth) ? ct_a.add_depth : ct_b.add_depth;
  ct_out.mult_depth = (ct_a.mult_depth > ct_b.mult_depth) ? ct_a.mult_depth + 1 : ct_b.mult_depth + 1;
}

void WalrusMult(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                const WalrusCtxt& ct_b, Evaluator& evaluator, 
                RelinKeys& ks_keys) {
  evaluator.multiply(ct_a.ctxt, ct_b.ctxt, ct_out.ctxt);
  evaluator.relinearize_inplace(ct_out.ctxt, ks_keys);
  if (ct_a.scheme == scheme_type::ckks) {
    evaluator.rescale_to_next_inplace(ct_out.ctxt);
    ct_out.ctxt.scale() = ct_out.scale;
  } else {
    evaluator.mod_switch_to_next_inplace(ct_out.ctxt);
  }
}

void WalrusMultPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                     const Plaintext& pt_b) {
  ct_out.mult_depth = ct_a.mult_depth + 1;
  ct_out.add_depth = ct_a.add_depth;
}

void WalrusMultPlain(WalrusCtxt& ct_out, const WalrusCtxt& ct_a, 
                     const Plaintext& pt_b, Evaluator& evaluator) {
  evaluator.multiply_plain(ct_a.ctxt, pt_b, ct_out.ctxt);
}