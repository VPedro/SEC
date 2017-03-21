# SEC

Our project already includes 2 keystores. But if needed run 1st step (Generate keystore) to generate new ones.


File 'keystorefile.jce' already includes the following pairs of (alias, password):
 - (alias, olaola)
 - (alias1, olaola)
 - (alias2, olaola)


File 'serverkeystorefile.jce' with:
 - (server, olaola)
 
 
# 1. Generate keystores 
`cd SEC/src` <br><br>
In order to simulate that the Keys are generated in a secure way, run keytool on src folder with the following commands:
<br>`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias server -keyalg RSA -keysize 2048 -keystore serverkeystorefile.jce -validity 365  -storetype JCEKS` <br><br>
(Repeat the following with different alias to simulate different clients)
<br>`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias alias -keyalg RSA -keysize 2048 -keystore keystorefile.jce -validity 365  -storetype JCEKS` <br><br>

# 2. Running Server
`cd SEC/src` <br>
`javac pt/ist/sec/proj/*.java` <br>
`java pt.ist.sec.proj.Server` <br>

# 3. Running Client
`cd SEC/src` <br>
`javac pt/ist/sec/proj/*.java` <br>
`java pt.ist.sec.proj.Client` <br>


# TODO
`When the same client is logged in two processes and one of them closes, the other frozens`<br>
