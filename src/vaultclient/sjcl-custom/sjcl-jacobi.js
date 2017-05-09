import sjcl from '../sjcl'; 

export default function jacobi(a, that) {
  that = new sjcl.bn(that);

  let neg = !that.greaterEquals(new sjcl.bn(0));
  if (neg) return;

  // 1. If a = 0 then return(0).
  if (a.equals(0)) { return 0; }

  // 2. If a = 1 then return(1).
  if (a.equals(1)) { return 1; }

  let s = 0;
  // 3. Write a = 2^e * a1, where a1 is odd.
  let e = 0;
  const a1 = new sjcl.bn(a);
  while ((a1.getLimb(0) & 1) === 0) {
    e++;
    a1.halveM();
  }

  // 4. If e is even then set s ← 1.
  if ((e & 1) === 0) {
    s = 1;
  } else {
    const residue = that.getLimb(0) & 7;

    if (residue === 1 || residue === 7) {
      // Otherwise set s ← 1 if n ≡ 1 or 7 (mod 8)
      s = 1;
    } else if (residue === 3 || residue === 5) {
      // Or set s ← −1 if n ≡ 3 or 5 (mod 8).
      s = -1;
    }
  }

  // 5. If n ≡ 3 (mod 4) and a1 ≡ 3 (mod 4) then set s ← −s.
  if ((that.getLimb(0) & 3) === 3 && (a1.getLimb(0) & 3) === 3) {
    s = -s;
  }

  if (a1.equals(1)) {
    return s;
  }
  return s * jacobi(that.mod(a1), a1);
}
