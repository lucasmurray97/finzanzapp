from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Usuarios
class User(AbstractUser):
    # Nombre que aparecerá en la página
    display_name = models.CharField(max_length=100, blank=True)
    # Monto, parte en 0
    total = models.FloatField(default=0)
    # Presupuesto, opcional
    budget = models.FloatField(blank=True, null=True)
    # Configuracion de GPT para sugerir categorias
    use_gpt = models.BooleanField(default=False)
    openai_api_key = models.CharField(max_length=200, blank=True, null=True)


# Categorias 
class Category(models.Model):
    # Nombre de la categoria
    name = models.CharField(max_length=100)
    # Presupuesto asociado a la categoria, opcional
    budget = models.FloatField(blank=True)
    # Usuario que creo la categoría
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="categories", null=True)
    

# Transacciones
class Transaction(models.Model):
    # Tiene un único usuario asociado
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="transactions")
    # Descripción de la transaccion
    description = models.TextField(max_length=500)
    # Monto de la transacción
    amount = models.FloatField(default=0)
    # Fecha de la transacción
    date = models.DateField(default=timezone.now().strftime("%Y-%m-%d"))
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name="transactions", blank=True, null=True)


class MonthlyBudget(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="monthly_budgets")
    month = models.DateField()
    salary = models.FloatField(default=0)
    budget = models.FloatField(default=0)
    debts = models.FloatField(default=0)
    savings_goal = models.FloatField(default=0)

    class Meta:
        unique_together = ("user", "month")


class SavingsWithdrawal(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="savings_withdrawals")
    amount = models.FloatField(default=0)
    date = models.DateField(default=timezone.now)
    note = models.CharField(max_length=200, blank=True)


class GmailCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="gmail_credentials")
    email = models.EmailField()
    credentials_json = models.TextField()
    last_synced_at = models.DateTimeField(blank=True, null=True)


class GmailMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="gmail_messages")
    gmail_id = models.CharField(max_length=200)
    subject = models.CharField(max_length=255, blank=True)
    snippet = models.TextField(blank=True)
    amount = models.FloatField(default=0)
    merchant = models.CharField(max_length=200, blank=True)
    account = models.CharField(max_length=50, blank=True)
    purchase_date = models.DateField(blank=True, null=True)
    purchase_time = models.TimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "gmail_id")
