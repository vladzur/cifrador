<?php namespace Vladzur\Cifrador;
/*
 *      Cifrador.php
 *
 *      Copyright 2011 Vladimir Zurita <vladzur@gmail.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 *
 *
 */


/**
 * Clase para cifrar y descifrar textos utilizando la función mcryt en modo CFB
 * y el algoritmo Rijndael 256 (AES).
 * Es capaz de generar contraseñas aleatorias y generar textos cifrados como
 * binarios o en base 64.
 *
 * @author Vladimir Zurita
 */
class Cifrador
{

    private $clave;
    private $iv;

    /**
     * Alias for Cifrador::cifrar()
     * @param $text
     * @param $password
     * @return string
     */
    public function encrypt($text, $password)
    {
        return $this->cifrar($text, $password);
    }

    /**
     * Cifra un texto utilizando el algoritmo Rijndael_256 (AES), retornando el texto
     * como binario o en base 64.
     *
     * @param string $texto Texto a cifrar
     * @param string $password Contraseña para cifrar
     * @return string Texto cifrado
     */
    public function cifrar($texto, $password)
    {
        $this->generarClave($password);
        if (empty($this->iv)) {
            $this->generarIV();
        }
        $resultado = $this->iv . mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->clave, $texto, MCRYPT_MODE_CFB, $this->iv);
        return base64_encode($resultado);
    }

    /**
     * Genera una clave binaria de la contraseña entregada usando el algoritmo SHA256.
     *
     * @param string $password Contraseña para generar la clave
     */
    private function generarClave($password)
    {
        $this->clave = hash('SHA256', $password, true);
    }

    /**
     * Genera el vector de inicialización (IV) para el algoritmo Rijndael_256 (AES).
     */
    private function generarIV()
    {
        $this->iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CFB), MCRYPT_DEV_URANDOM);
    }

    /**
     * Alias for Cifrador::descifrar()
     * @param $text
     * @param $password
     * @return string
     */
    public function decrypt($text, $password)
    {
        return $this->descifrar($text, $password);
    }

    /**
     * Descifra un texto utilizando el algoritmo Rijndael_256 (AES) retornando el texto en claro.
     *
     * @param string $text Texto a descifrar, puede estar en binario o base 64
     * @param string $password La contraseña que se usó para cifrar
     * @param bool $base64 Indica si el texto a descifrar está en base 64 o no
     * @return string Texto descifrado.
     */
    public function descifrar($texto, $password)
    {
        $this->generarClave($password);
        $resultado = base64_decode($texto);
        $iv = substr($resultado, 0, 32);
        $cifrado = substr($resultado, 32);
        $descifrado = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->clave, $cifrado, MCRYPT_MODE_CFB, $iv);
        return $descifrado;
    }

    /**
     * Genera una contraseña aleatoria de largo indicado.
     * Basado en ejemplo mt_rand() en php.net
     *
     * @param int $largo Cantidad de caracteres de la contraseña default 16.
     * @return string Contraseña generada.
     */
    public function generarPassword($largo = 16)
    {
        $password = '';
        for ($i = 0; $i < $largo; ++$i) {
            if ($i % 2 == 0) {
                mt_srand(time() % 2147 * 1000000 + (double)microtime() * 1000000);
            }
            $rnd = mt_rand(48, 122);
            if ($rnd > 57 && $rnd < 65) {
                $rnd += 6;
            }
            if ($rnd > 90 && $rnd < 97) {
                $rnd += 7;
            }
            $password .= chr($rnd);
        }
        return $password;
    }

    /**
     * Genera un hash usando el algoritmo SHA1.
     *
     * @param string $texto Texto para generar hash
     * @param bool $raw Tipo de hash binario (true) o base64 (false)
     * @return string Hash
     */
    public function generarHash($texto, $raw = false)
    {
        return hash('SHA1', $texto, $raw);
    }

}