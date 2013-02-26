<?php
/*
 *      cifrado.php
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
class Cifrado {

	private $clave = '';
	private $iv = '';
	private $iv64 = '';

	/**
	 * Cifra un texto utilizando el algoritmo Rijndael_256 (AES), retornando el texto
	 * como binario o en base 64.
	 *
	 * @param string $texto Texto a cifrar
	 * @param string $password Contraseña para cifrar
	 * @param bool $base64 Indicar si se retornará binario o base 64.
	 * @return string Texto cifrado
	 */
	public function cifrar($texto, $password, $base64 = true) {
		$this->generarClave($password);
		if (empty($this->iv)) {
			$this->generarIV();
		}
		$resultado = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->clave, $texto, MCRYPT_MODE_CFB, $this->iv);
		if ($base64 === true) {
			return base64_encode($resultado);
		}
		return $resultado;
	}

	/**
	 * Descifra un texto utilizando el algoritmo Rijndael_256 (AES) retornando el texto en claro.
	 *
	 * @param string $text Texto a descifrar, puede estar en binario o base 64
	 * @param string $password La contraseña que se usó para cifrar
	 * @param bool $base64 Indica si el texto a descifrar está en base 64 o no
	 * @return string Texto descifrado.
	 */
	public function descifrar($texto, $password = null, $base64 = true) {
		$this->generarClave($password);
		$iv = $this->iv;
		if ($base64 === true) {
			$texto = base64_decode($texto);
			$iv = base64_decode($this->iv64);
		}
		$resultado = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->clave, $texto, MCRYPT_MODE_CFB, $iv);
		return $resultado;
	}

	/**
	 * Genera el vector de inicialización (IV) para el algoritmo Rijndael_256 (AES).
	 */
	private function generarIV() {
		$this->iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CFB), MCRYPT_DEV_URANDOM);
		$this->iv64 = base64_encode($this->iv);
	}

	/**
	 * Genera una clave binaria de la contraseña entregada usando el algoritmo SHA256.
	 *
	 * @param string $password Contraseña para generar la clave
	 */
	private function generarClave($password) {
		$this->clave = hash('SHA256', $password, true);
	}

	/**
	 * Genera un hash usando el algoritmo SHA1.
	 *
	 * @param string $texto Texto para generar hash
	 * @param bool $raw Tipo de hash binario (true) o base64 (false)
	 * @return string Hash
	 */
	private function generarHash($texto, $raw = false) {
		return hash('SHA1', $texto, $raw);
	}

	/**
	 * Genera una contraseña aleatoria de largo indicado.
	 * Basado en ejemplo mt_rand() en php.net
	 *
	 * @param int $largo Cantidad de caracteres de la contraseña default 16.
	 * @return string Contraseña generada.
	 */
	public function generarPassword($largo = 16) {
		for ($i = 0; $i < $largo; ++$i) {
			if ($i % 2 == 0) {
				mt_srand(time() % 2147 * 1000000 + (double) microtime() * 1000000);
			}
			$rnd = mt_rand(48, 122);
			if ($rnd > 57 && $rnd < 65) {
				$rnd +=6;
			}
			if ($rnd > 90 && $rnd < 97) {
				$rnd +=7;
			}
			$password.=chr($rnd);
		}
		return $password;
	}

	/**
	 * Asigna un vector de inicialización (IV) en base 64 para ser usado
	 * en el cifrado/descifrado.
	 *
	 * @param string $iv64 IV en base 64
	 */
	public function setIV($iv64) {
		$this->iv = base64_decode($iv64);
		$this->iv64 = $iv64;
	}

	/**
	 * Accesador de la propiedad iv64
	 * @return string
	 */
	public function getIv64() {
		return $this->iv64;
	}

}

?>
