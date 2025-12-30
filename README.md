# 2023-1-Grupo-2

Finanzapp es una aplicación web creada utilizando Django, que permite al usuario llevar registro de sus movimientos financieros, así como ayudarlo a organizarlos de manera intuitiva.

Actualmente permite al usuario crear una cuenta, con la cual puede ingresar transacciones al sistema, que pueden ser ingresos o gastos, y asignarles un valor, una descripción y una categoría. En la vista principal, se le muestra al usuario el saldo global de su cuenta, el formulario usado para ingresar transacciones al sistema y un resumen del estado de sus categorías. Estas categorías son creadas por el usuario desde la sección *Organizate*, desde donde puede asignarles un nombre y un presupuesto, además de poder ajustar su presupuesto global.

Si se desea ver un listado de todas las transacciones que el usuario ha ingresado a la aplicación, puede hacerlo desde la sección *Transacciones*. Esta presenta todas las transacciones separadas por categorías, y permite editarlas o eliminarlas. También cuenta con filtros de fecha o de categoría, por si se necesita buscar una transacción específica.

Por último, para cerrar la sesión hay que hacer click en la sección *Logout*.

Para correr la aplicación se necesita tener instaladas las librerías indicadas en el archivo *requirements.txt*, o instalarlas en un entorno virtual y activarlo para ejecutar la aplicación. Luego, se debe entrar a la carpeta *finanzapp_proj* ejecutar el comando.

```
python manage.py runserver
```

Esto iniciará la aplicación en la dirección *http://127.0.0.1:8000/*. Al acceder a la dirección se mostrará el formulario de inicio de sesión. Si no se tiene una cuenta, hay un link al formulario de registro bajo el formulario. Una vez registrado, se inicia sesión y se redirige al usuario a la vista principal, desde donde se puede acceder a todas las funcionalidades de Finanzapp.

## Gmail + GPT (nuevas funciones)

Para sincronizar Gmail automáticamente debes configurar credenciales OAuth en Google Cloud y definir las variables de entorno:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI` (por ejemplo `http://127.0.0.1:8000/gmail/callback/`)

### .env local (opcional)

Puedes crear un archivo `.env` en la raíz del repo (usa `.env.example` como plantilla) y el servidor lo cargará automáticamente al iniciar.

Para categorización automática con GPT, agrega tu API key desde la sección “Organízate”. Cada usuario guarda su propia key y puede activar/desactivar GPT.
