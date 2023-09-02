`govrfy` eats a pem certificate file and outputs another pem file
with complete certificate chain from it.

Use it as follows:

	govrfy -in <in pem> -out <out pem>

If you want out pem to contain ca certificates only use this:

	govrfy -ca -in <in pem> -out <out.pem>

