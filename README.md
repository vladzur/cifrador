[![Codacy Badge](https://api.codacy.com/project/badge/grade/10f0481ba48e4a518da665fcc77c6c9c)](https://www.codacy.com/app/vladzur/cifrador)

##Cifrador

Encrypt and decrypt strings using AES

###Usage

    <?php
    $Cifrador = new Cifrador();
    
    //Encrypt text
    $texto_cifrado = $Cifrador->cifrar("Este texto será cifrado", "m1p4ssw0rd");
    echo $texto_cifrado;
    
    //Decrypt text
    $texto = $Cifrador->descifrar($texto_cifrado, "m1p4ssw0rd");
    echo $texto;
    ?>
    


