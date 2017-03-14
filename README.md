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

# Generate keys to keystore
`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias rgateway -keyalg RSA -keysize 2048 -keystore keystorefile.jce -validity 365  -storetype JCEKS` <br>

# TO DO
`Create registerMessage(PublicKey, Signature, response)`<br>
`Save must encript data`<br>
`Retrieve must encript data`<br>
`Library calls getNounce on Init`<br>
`Verify FIXME's`<br>

`HardMode:`<br>
  `Encrypt Domain and Username`<br>
