// Govrfy eats a pem certificate and complete it to a certificate chain
// in pem format..
//
// Usage:
//
//	govrfy -in <in pem> -out <out pem>
//
// if out pem file should only contain ca certificates, use:
//
//	govrfy -ca -in <in pem> -out <out pem>
package main
