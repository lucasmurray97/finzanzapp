"""
URL configuration for finanzapp_proj project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from finanzapp.views import index, login_1, register, logout_view, list_transactions, edit_trans, actualizar_trans, delete_trans, organize_fin, delete_cat, edit_cat, actualizar_cat, add_transaction_email, transfer_debt, gmail_connect, gmail_callback, gmail_sync, gmail_sync_cron, suggest_category, add_savings_withdrawal

urlpatterns = [
    path('', index, name='index'),
    path('admin/', admin.site.urls, name='admin'),
    path('login/', login_1, name='login'),
    path('register/', register, name='register_user'),
    path('logout/', logout_view, name='logout'),
    path('list/', list_transactions, name='list'),
    path('organiza_tus_finanzas/', organize_fin, name='organiza_finanzas'),
    path('editTrans/<int:id_transaccion>', edit_trans, name='edit_trans'),
    path('actualizarTrans/<int:id_transaccion>', actualizar_trans, name='actualizar_trans'),
    path('eliminarTrans/<int:id_transaccion>', delete_trans, name='eliminar_trans'),
    path('eliminarCat/<int:id_categoria>', delete_cat, name='eliminar_cat'),
    path('editCat/<int:id_categoria>', edit_cat, name='eliminar_cat',),
    path('actualizarCat/<int:id_categoria>', actualizar_cat, name='actualizar_cat'),
    path('addFromEmail/', add_transaction_email, name="add_transaction_email"),
    path('transferDebt/<int:id_categoria>', transfer_debt, name='transfer_debt',),
    path('gmail/connect/', gmail_connect, name='gmail_connect'),
    path('gmail/callback/', gmail_callback, name='gmail_callback'),
    path('gmail/sync/', gmail_sync, name='gmail_sync'),
    path('gmail/sync/cron/', gmail_sync_cron, name='gmail_sync_cron'),
    path('suggestCategory/', suggest_category, name='suggest_category'),
    path('savings/withdraw/', add_savings_withdrawal, name='add_savings_withdrawal'),
]
