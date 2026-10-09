#!/usr/bin/env python3
"""Bounded negative controls in an owned source copy, never mutate the checkout."""
import argparse, json, os, pathlib, shutil, subprocess, time
parser=argparse.ArgumentParser();parser.add_argument('--source',required=True);parser.add_argument('--target',required=True);parser.add_argument('--report',required=True);args=parser.parse_args()
repo=pathlib.Path(__file__).resolve().parents[1];source=pathlib.Path(args.source);target=pathlib.Path(args.target);report=pathlib.Path(args.report)
if source.exists():raise SystemExit('Refusing to overwrite source copy')
source.mkdir(parents=True);report.mkdir(parents=True,exist_ok=True)
files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=repo,text=True).splitlines()
for rel in files+['Cargo.lock']:
 src=repo/rel
 if src.is_file():dest=source/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
mutants=[
 ('length','ipa-multipoint/src/ipa.rs','if len != expected {','if false && len != expected {','ipa-multipoint','hardening','proof_lengths_and_dimensions_return_errors'),
 ('shape','ipa-multipoint/src/ipa.rs','&& self.R_vec.len() == self.L_vec.len()','&& true','ipa-multipoint','hardening','malformed_verifier_shapes_fail_without_panics'),
 ('Q','ipa-multipoint/src/ipa.rs','let q_i = w * (output_point + self.a * b_0);','let q_i = Fr::zero();','ipa-multipoint','lib','test_ipa_consistency'),
 ('b0','ipa-multipoint/src/ipa.rs','let q_i = w * (output_point + self.a * b_0);','let q_i = w * output_point;','ipa-multipoint','lib','test_ipa_consistency'),
 ('sign','ipa-multipoint/src/ipa.rs','folding_coefficients(&challenges_inv, -Fr::one())','folding_coefficients(&challenges_inv, Fr::one())','ipa-multipoint','lib','test_ipa_consistency'),
 ('transcript','ipa-multipoint/src/transcript.rs','self.state.update(label);\n        self.state.update(message);','self.state.update(message);','ipa-multipoint','lib','test_vector_2'),
 ('replay','ipa-multipoint/src/streaming.rs','if first.finalize() != replay.finalize() {','if false {','ipa-multipoint','streaming','prover_replay_binds_polynomial_identity_even_when_statement_matches'),
 ('quotient','banderwagon/src/trait_impls/serialize.rs','&& (z2 - BandersnatchConfig::COEFF_A * x2).legendre().is_qr()','&& true','banderwagon','lib','on_curve_wrong_coset_is_rejected'),
 ('full_key','ipa-multipoint/src/streaming.rs',None,None,'ipa-multipoint','streaming','grouping_uses_the_entire_canonical_commitment_key'),
]
env=os.environ.copy();env['RAYON_NUM_THREADS']='1'
results=[]
def run(name, package, test, filter):
 command=['cargo','test','--manifest-path',str(source/'Cargo.toml'),'--target-dir',str(target),'-p',package]
 command+=['--lib'] if test=='lib' else ['--test',test]
 command += [filter]
 start=time.time()
 with (report/(name+'.log')).open('w') as output:
  result=subprocess.run(command,env=env,stdout=output,stderr=subprocess.STDOUT)
 text=(report/(name+'.log')).read_text()
 ran_test='running 1 test' in text and ('test result: FAILED' in text or 'test result: ok' in text)
 return {'name':name,'exit_code':result.returncode,'executed_test':ran_test,'killed':result.returncode!=0 and ran_test,'duration_seconds':time.time()-start,'command':command}
# Positive controls demonstrate the filters actually run on the candidate.
for _,_,_,_,package,test,filter in mutants:
 key=f'{package}:{test}:{filter}'
 if any(r.get('positive_filter')==key for r in results):continue
 result=run('positive-'+filter,package,test,filter);result['positive_filter']=key
 if result['exit_code']!=0 or not result['executed_test']:raise RuntimeError('Positive control failed: '+filter)
 results.append(result)
for name,rel,before,after,package,test,filter in mutants:
 path=source/rel;original=path.read_text();modified=original
 if name=='full_key':
  # Truncate BOTH insert and lookup, so failure requires an actual key collision.
  modified=modified.replace('.entry(query.commitment.bytes)', '.entry(prefix_key(query.commitment.bytes))').replace('.get(&query.commitment.bytes)', '.get(&prefix_key(query.commitment.bytes))')
  modified+='\nfn prefix_key(bytes:[u8;32])->[u8;32] {let mut key=[0;32];key[0]=bytes[0];key}\n'
 else:
  if before not in original:raise RuntimeError('Mutation target absent: '+name)
  modified=modified.replace(before,after)
 path.write_text(modified)
 try:results.append(run(name,package,test,filter))
 finally:path.write_text(original)
 (report/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(name,'KILLED' if results[-1]['killed'] else 'SURVIVED or did not execute',flush=True)
if not all(r['killed'] for r in results if 'positive_filter' not in r):raise SystemExit(1)
