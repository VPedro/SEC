# SEC
SEC Project


# Running Server
`cd SEC/src` <br>
`javac pt/ist/sec/proj/*.java` <br>
`java pt.ist.sec.proj.Server` <br>

# Running Client
`cd SEC/src` <br>
`javac pt/ist/sec/proj/*.java` <br>
`java pt.ist.sec.proj.Client` <br>

# Generate client's keystore
`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias alias -keyalg RSA -keysize 2048 -keystore keystorefile.jce -validity 365  -storetype JCEKS` <br>

# Generate server's keystore
`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias server -keyalg RSA -keysize 2048 -keystore serverkeystorefile.jce -validity 365  -storetype JCEKS` <br>

# TO DO
`Create registerMessage(PublicKey, Signature, response)`<br>
`Save must encript data`<br>
`Retrieve must encript data`<br>
`Library calls getNounce on Init`<br>
`Verify FIXME's`<br>
`Verify server signatures `<br>
`send new nounce on every func (therad calling server.getNounce e depois manda isso  encriptado com a priv Serv e a assinado pelo serv`<br>

`HardMode:`<br>
  `Encrypt Domain and Username`<br>
