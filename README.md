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
    


