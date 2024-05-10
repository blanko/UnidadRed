# UnidadRed

UnidadRed es una aplicación de consola en C# que automatiza la configuración de una unidad de red en Windows, gestionando de manera segura las credenciales y configuraciones a través de un archivo cifrado.

## Características

- Registro automático para ejecución al iniciar Windows.
- Cifrado y descifrado de configuraciones usando AES.
- Actualización y lectura de configuraciones desde un archivo `.config`.

## Requisitos

- .NET 6.0 o superior
- Sistema operativo Windows (debido al uso de `Microsoft.Win32` y configuraciones específicas del sistema operativo)

## Instalación

Clona el repositorio a tu máquina local usando:

```bash
git clone https://github.com/tu-usuario/UnidadRed.git
```
