# SEC
SEC Project

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
