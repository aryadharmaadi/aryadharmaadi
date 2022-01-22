import wfuzz
from fuzzingbook.WebFuzzer import GrammarFuzzer, is_valid_grammar
from fuzzingbook.Grammars import srange
from fuzzingbook.WebFuzzer import cgi_encode
import string
import datetime

#for r in wfuzz.get_payload(range(100)).fuzz(hl=[97], url="http://testphp.vulnweb.com/listproducts.php?cat=FUZZ"):
#    print (r)

REGISTER_GRAMMAR = {
    "<start>": ["<order>"],
    "<order>": ["userid=<identifier>&nama=<identifier>&alamat=<identifier>"],
    "<identifier>": ["<idchar>", "<identifier><idchar>"],
    "<idchar>": (srange(string.printable))
}

assert is_valid_grammar(REGISTER_GRAMMAR)

order_fuzzer = GrammarFuzzer(REGISTER_GRAMMAR, log=False, min_nonterminals=9, max_nonterminals=30)
seed = [order_fuzzer.fuzz() for i in range(20)]

filename = "text.txt"
f = open(filename, "w")
for s in seed:
    s = repr(s)
    f.write(s[1:len(s)-1])
    f.write("\n")
f.close()

ct = datetime.datetime.now()
for r in wfuzz.fuzz(url="http://192.168.0.105/testing/reg-post.php", printer=("output/"+ct.strftime('%d%m%Y %H%M%S')+".txt", "raw"), postdata="FUZZ", payloads=[("file",dict(fn=filename))]):

#for r in wfuzz.fuzz(url="http://192.168.0.105/testing/reg-post.php", postdata="FUZZ", payloads=[("file",dict(fn=seed))]):
    print (r)
