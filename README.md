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

# Generate client's keystore (pass = olaola)
`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias alias -keyalg RSA -keysize 2048 -keystore keystorefile.jce -validity 365  -storetype JCEKS` <br>

# Generate 2nd client's keystore (pass = cl2pass)
`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias client1 -keyalg RSA -keysize 2048 -keystore keystorefile1.jce -validity 365  -storetype JCEKS` <br>

# Generate 3rd client's keystore (pass = cl3pass)
`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias client2 -keyalg RSA -keysize 2048 -keystore keystorefile2.jce -validity 365  -storetype JCEKS` <br>

# Generate server's keystore
`keytool -genkeypair -dname "CN=gateway.mycompany.com, O=My Company, C=US" -alias server -keyalg RSA -keysize 2048 -keystore serverkeystorefile.jce -validity 365  -storetype JCEKS` <br>

# TO DO
`Verify FIXME's`<br>

`HardMode:`<br>
  `Encrypt Domain and Username`<br>
