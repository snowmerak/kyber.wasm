package main

import (
	"crypto/rand"
	"log"
	"syscall/js"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func main() {
	log.Println("Load Kyber.WASM")
	js.Global().Set("newKeyPair512", js.FuncOf(newKeyPair512))
	js.Global().Set("newKeyPair768", js.FuncOf(newKeyPair768))
	js.Global().Set("newKeyPair1024", js.FuncOf(newKeyPair1024))
	js.Global().Set("encrypt512", js.FuncOf(encrypt512))
	js.Global().Set("decrypt512", js.FuncOf(decrypt512))
	js.Global().Set("encrypt768", js.FuncOf(encrypt768))
	js.Global().Set("decrypt768", js.FuncOf(decrypt768))
	js.Global().Set("encrypt1024", js.FuncOf(encrypt1024))
	js.Global().Set("decrypt1024", js.FuncOf(decrypt1024))
	select {}
}

func newKeyPair512(_ js.Value, _ []js.Value) interface{} {
	result := map[string]interface{}{}
	pub, prive, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	buf := make([]byte, pub.Scheme().PublicKeySize())
	pub.Pack(buf)
	result["public"] = make([]interface{}, len(buf))
	for i := 0; i < len(buf); i++ {
		result["public"].([]interface{})[i] = buf[i]
	}
	buf = make([]byte, prive.Scheme().PrivateKeySize())
	prive.Pack(buf)
	result["private"] = make([]interface{}, len(buf))
	for i := 0; i < len(buf); i++ {
		result["private"].([]interface{})[i] = buf[i]
	}
	return result
}

func encrypt512(_ js.Value, args []js.Value) interface{} {
	result := map[string]interface{}{}

	priv := make([]byte, args[0].Length())
	for i := 0; i < len(priv); i++ {
		priv[i] = byte(args[0].Index(i).Int())
	}
	pub := make([]byte, args[1].Length())
	for i := 0; i < len(pub); i++ {
		pub[i] = byte(args[1].Index(i).Int())
	}

	privKey := new(kyber512.PrivateKey)
	privKey.Unpack(priv)
	pubKey := new(kyber512.PublicKey)
	pubKey.Unpack(pub)

	seed := make([]byte, pubKey.Scheme().EncapsulationSeedSize())
	rand.Read(seed)
	sharedKey := make([]byte, pubKey.Scheme().SharedKeySize())
	cipherText := make([]byte, pubKey.Scheme().CiphertextSize())
	pubKey.EncapsulateTo(cipherText, sharedKey, seed)
	result["ciphertext"] = make([]interface{}, len(cipherText))
	for i := 0; i < len(cipherText); i++ {
		result["ciphertext"].([]interface{})[i] = cipherText[i]
	}
	result["shared"] = make([]interface{}, len(sharedKey))
	for i := 0; i < len(sharedKey); i++ {
		result["shared"].([]interface{})[i] = sharedKey[i]
	}
	return result
}

func decrypt512(_ js.Value, args []js.Value) interface{} {
	result := map[string]interface{}{}

	priv := make([]byte, args[0].Length())
	for i := 0; i < len(priv); i++ {
		priv[i] = byte(args[0].Index(i).Int())
	}

	privKey := new(kyber512.PrivateKey)
	privKey.Unpack(priv)

	cipher := make([]byte, args[1].Length())
	for i := 0; i < len(cipher); i++ {
		cipher[i] = byte(args[1].Index(i).Int())
	}

	shared := make([]byte, privKey.Scheme().SharedKeySize())

	privKey.DecapsulateTo(shared, cipher)
	result["shared"] = make([]interface{}, len(shared))
	for i := 0; i < len(shared); i++ {
		result["shared"].([]interface{})[i] = shared[i]
	}

	return result
}

func newKeyPair768(_ js.Value, _ []js.Value) interface{} {
	result := map[string]interface{}{}
	pub, prive, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	buf := make([]byte, pub.Scheme().PublicKeySize())
	pub.Pack(buf)
	result["public"] = make([]interface{}, len(buf))
	for i := 0; i < len(buf); i++ {
		result["public"].([]interface{})[i] = buf[i]
	}
	buf = make([]byte, prive.Scheme().PrivateKeySize())
	prive.Pack(buf)
	result["private"] = make([]interface{}, len(buf))
	for i := 0; i < len(buf); i++ {
		result["private"].([]interface{})[i] = buf[i]
	}
	return result
}

func encrypt768(_ js.Value, args []js.Value) interface{} {
	result := map[string]interface{}{}

	priv := make([]byte, args[0].Length())
	for i := 0; i < len(priv); i++ {
		priv[i] = byte(args[0].Index(i).Int())
	}
	pub := make([]byte, args[1].Length())
	for i := 0; i < len(pub); i++ {
		pub[i] = byte(args[1].Index(i).Int())
	}

	privKey := new(kyber768.PrivateKey)
	privKey.Unpack(priv)
	pubKey := new(kyber768.PublicKey)
	pubKey.Unpack(pub)

	seed := make([]byte, pubKey.Scheme().EncapsulationSeedSize())
	rand.Read(seed)
	sharedKey := make([]byte, pubKey.Scheme().SharedKeySize())
	cipherText := make([]byte, pubKey.Scheme().CiphertextSize())
	pubKey.EncapsulateTo(cipherText, sharedKey, seed)
	result["ciphertext"] = make([]interface{}, len(cipherText))
	for i := 0; i < len(cipherText); i++ {
		result["ciphertext"].([]interface{})[i] = cipherText[i]
	}
	result["shared"] = make([]interface{}, len(sharedKey))
	for i := 0; i < len(sharedKey); i++ {
		result["shared"].([]interface{})[i] = sharedKey[i]
	}
	return result
}

func decrypt768(_ js.Value, args []js.Value) interface{} {
	result := map[string]interface{}{}

	priv := make([]byte, args[0].Length())
	for i := 0; i < len(priv); i++ {
		priv[i] = byte(args[0].Index(i).Int())
	}

	privKey := new(kyber768.PrivateKey)
	privKey.Unpack(priv)

	cipher := make([]byte, args[1].Length())
	for i := 0; i < len(cipher); i++ {
		cipher[i] = byte(args[1].Index(i).Int())
	}

	shared := make([]byte, privKey.Scheme().SharedKeySize())

	privKey.DecapsulateTo(shared, cipher)
	result["shared"] = make([]interface{}, len(shared))
	for i := 0; i < len(shared); i++ {
		result["shared"].([]interface{})[i] = shared[i]
	}

	return result
}

func newKeyPair1024(_ js.Value, _ []js.Value) interface{} {
	result := map[string]interface{}{}
	pub, prive, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	buf := make([]byte, pub.Scheme().PublicKeySize())
	pub.Pack(buf)
	result["public"] = make([]interface{}, len(buf))
	for i := 0; i < len(buf); i++ {
		result["public"].([]interface{})[i] = buf[i]
	}
	buf = make([]byte, prive.Scheme().PrivateKeySize())
	prive.Pack(buf)
	result["private"] = make([]interface{}, len(buf))
	for i := 0; i < len(buf); i++ {
		result["private"].([]interface{})[i] = buf[i]
	}
	return result
}

func encrypt1024(_ js.Value, args []js.Value) interface{} {
	result := map[string]interface{}{}

	priv := make([]byte, args[0].Length())
	for i := 0; i < len(priv); i++ {
		priv[i] = byte(args[0].Index(i).Int())
	}
	pub := make([]byte, args[1].Length())
	for i := 0; i < len(pub); i++ {
		pub[i] = byte(args[1].Index(i).Int())
	}

	privKey := new(kyber1024.PrivateKey)
	privKey.Unpack(priv)
	pubKey := new(kyber1024.PublicKey)
	pubKey.Unpack(pub)

	seed := make([]byte, pubKey.Scheme().EncapsulationSeedSize())
	rand.Read(seed)
	sharedKey := make([]byte, pubKey.Scheme().SharedKeySize())
	cipherText := make([]byte, pubKey.Scheme().CiphertextSize())
	pubKey.EncapsulateTo(cipherText, sharedKey, seed)
	result["ciphertext"] = make([]interface{}, len(cipherText))
	for i := 0; i < len(cipherText); i++ {
		result["ciphertext"].([]interface{})[i] = cipherText[i]
	}
	result["shared"] = make([]interface{}, len(sharedKey))
	for i := 0; i < len(sharedKey); i++ {
		result["shared"].([]interface{})[i] = sharedKey[i]
	}
	return result
}

func decrypt1024(_ js.Value, args []js.Value) interface{} {
	result := map[string]interface{}{}

	priv := make([]byte, args[0].Length())
	for i := 0; i < len(priv); i++ {
		priv[i] = byte(args[0].Index(i).Int())
	}

	privKey := new(kyber1024.PrivateKey)
	privKey.Unpack(priv)

	cipher := make([]byte, args[1].Length())
	for i := 0; i < len(cipher); i++ {
		cipher[i] = byte(args[1].Index(i).Int())
	}

	shared := make([]byte, privKey.Scheme().SharedKeySize())

	privKey.DecapsulateTo(shared, cipher)
	result["shared"] = make([]interface{}, len(shared))
	for i := 0; i < len(shared); i++ {
		result["shared"].([]interface{})[i] = shared[i]
	}

	return result
}
