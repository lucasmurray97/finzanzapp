from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect, render
from finanzapp.models import (
    User,
    Transaction,
    Category,
    MonthlyBudget,
    SavingsWithdrawal,
    GmailCredential,
    GmailMessage,
    CronLock,
)
from finanzapp.forms import RegisterUserForm, EditTransactionForm, EditCategoryForm
from django.utils import timezone
from django.db.models import Sum
from django.db import IntegrityError, transaction, close_old_connections
import sys
from django.views.decorators.csrf import csrf_exempt
import json
import datetime
from datetime import timedelta
import threading
import base64
import os
import re
import html
import logging
import urllib.request
import urllib.parse
# Create your views here.

# Logs to the Django console for sync debugging.
logger = logging.getLogger(__name__)

def _acquire_cron_lock(name, timeout_seconds=1200):
    now = timezone.now()
    with transaction.atomic():
        lock, created = CronLock.objects.select_for_update().get_or_create(
            name=name,
            defaults={"locked_at": now},
        )
        if not created and lock.locked_at and lock.locked_at > now - timedelta(seconds=timeout_seconds):
            return False
        lock.locked_at = now
        lock.save(update_fields=["locked_at"])
        return True

def _release_cron_lock(name):
    CronLock.objects.filter(name=name).update(locked_at=None)

def _run_gmail_month_sync(user_id, month_date, resync):
    close_old_connections()
    try:
        user = User.objects.get(id=user_id)
        month_start = _month_start(month_date)
        if resync:
            month_range_start, month_range_end = _month_range(month_start)
            Transaction.objects.filter(
                user=user,
                date__gte=month_range_start,
                date__lt=month_range_end,
            ).delete()
            GmailMessage.objects.filter(
                user=user,
                purchase_date__gte=month_range_start,
                purchase_date__lt=month_range_end,
            ).delete()
        page_token = None
        pages = 0
        while pages < 25:
            result = _sync_gmail_month(user, month_start, page_token=page_token)
            page_token = result.get("next_page_token")
            pages += 1
            if not page_token:
                break
    except Exception:
        logger.exception("Async Gmail resync failed for user=%s", user_id)
    finally:
        close_old_connections()

#-------------22/04/23----- Manuel y Felipe----->
def login_1(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')  # Redirigir al usuario a la página admin
        else:
           return render(request, 'login.html', {'error_message': 'Nombre de usuario o contraseña incorrectos'})
    else:
        return render(request, 'login.html')

#-------------22/04/23----- Diego y Gonzalo----->

def register(request):
    if request.method == 'GET': #Si estamos cargando la página
        form = RegisterUserForm()
        return render(request, "register_user.html", {"register_form": form}) #Mostrar el template

    elif request.method == 'POST': #Si se envía un formulario 
        #Se seleccionan los elementos del formulario con los que se creará el usuario
        nombre = request.POST['nombre']
        contraseña = request.POST['contraseña']
        display = request.POST['display_name']
        #Se crea el nuevo usuario
        user = User.objects.create_user(username=nombre, password=contraseña, display_name=display, budget=None)
        user.save()
        # Se crea la categoría ninguna por default:
        category = Category(name="ninguna", budget=0, user=user)
        category.save()
        #Se redirecciona al usuario a index, que será la pagina principal de la app.
        return redirect('index')

def logout_view(request): #View para cerrar sesión
    #Si está autenticado, cerramos la sesión
    if request.user.is_authenticated:
        logout(request)
    
    #Redirigimos al inicio de sesión
    return redirect('login')


#-----------------------------------------------12:00------>

#---------------29/04/2023--------Felipe, Lucas y Manuel---------->
#funcion auxiliar que devuelve el saldo disponible de cierto usuario
def saldo_disponible(user):
    user_id = user.id
    current_date = timezone.now().date()
    month = current_date.month
    gastos = Transaction.objects.filter(user_id=user_id, date__month=month).exclude(description="Transferencia interna").aggregate(Sum('amount'))['amount__sum'] or 0
    month_start = _month_start(current_date)
    month_budget = MonthlyBudget.objects.filter(user=user, month=month_start).first()
    if not month_budget or month_budget.budget is None:
        return 0, gastos
    budget = month_budget.budget - gastos
    #devuelve la resta entre depositos y gastos
    return budget, gastos

#Funcion auxiliar que devuelve el saldo de una categoria específica de un usuario
def saldo_categoría(user_id, cat):
    budget = cat.budget
    month = datetime.date.today().month
    gastos = Transaction.objects.filter(user_id=user_id, category=cat, date__month=month).aggregate(Sum('amount'))['amount__sum'] or 0
    saldo = budget - gastos
    return {'name': cat.name, "id": cat.id, 'amount': saldo, 'valid': (saldo >= 0)}

def _month_start(date_value):
    return date_value.replace(day=1)

def _next_month(date_value):
    if date_value.month == 12:
        return date_value.replace(year=date_value.year + 1, month=1, day=1)
    return date_value.replace(month=date_value.month + 1, day=1)

def _month_range(date_value):
    start = _month_start(date_value)
    end = _next_month(start)
    return start, end

def _month_label(date_value):
    return date_value.strftime("%b %Y")

def _shift_month(date_value, months):
    month_index = date_value.month - 1 + months
    year = date_value.year + (month_index // 12)
    month = (month_index % 12) + 1
    return date_value.replace(year=year, month=month, day=1)

def _decode_gmail_body(payload):
    if not payload:
        return ""
    body_data = payload.get("body", {}).get("data")
    if body_data:
        try:
            return base64.urlsafe_b64decode(body_data).decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            return ""
    parts = payload.get("parts", [])
    html_payloads = []
    for part in parts:
        mime_type = part.get("mimeType", "")
        if mime_type == "text/plain":
            decoded = _decode_gmail_body(part)
            if decoded:
                return decoded
        if mime_type == "text/html":
            html_payloads.append(part)
    for part in html_payloads:
        decoded = _decode_gmail_body(part)
        if decoded:
            cleaned = re.sub(r"(?is)<(script|style).*?>.*?</\\1>", " ", decoded)
            cleaned = re.sub(r"<[^>]+>", " ", cleaned)
            cleaned = html.unescape(cleaned)
            return cleaned
    for part in parts:
        decoded = _decode_gmail_body(part)
        if decoded:
            return decoded
    return ""

def _get_header(headers, name):
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""

def _extract_relevant_text(text):
    if not text:
        return ""
    lowered = text.lower()
    marker = "te informamos que se ha realizado una compra por"
    start = lowered.find(marker)
    if start != -1:
        snippet = text[start:]
        for stop in ["Revisa", "\n"]:
            stop_idx = snippet.find(stop)
            if stop_idx != -1:
                snippet = snippet[:stop_idx]
                break
        return snippet.strip().rstrip(".") + "."
    match = re.search(r"(Te informamos.*?)(Revisa|$)", text, re.IGNORECASE)
    if match:
        return match.group(1).strip().rstrip(".") + "."
    match = re.search(r"(compra por .*?)(?:\\.|$)", text, re.IGNORECASE)
    if match:
        return match.group(1).strip().rstrip(".") + "."
    return ""

_USD_TO_CLP_CACHE = {}

def _fetch_usd_to_clp_exchangerate_host(date_key):
    params = urllib.parse.urlencode(
        {
            "from": "USD",
            "to": "CLP",
            "amount": 1,
            "date": date_key,
        }
    )
    url = f"https://api.exchangerate.host/convert?{params}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            rate = payload.get("result")
            return float(rate) if rate is not None else None
    except Exception:
        logger.exception("Gmail sync: exchangerate.host failed for %s", date_key)
        return None

def _fetch_usd_to_clp_mindicador(rate_date):
    date_key = rate_date.strftime("%d-%m-%Y")
    url = f"https://mindicador.cl/api/dolar/{date_key}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            series = payload.get("serie") or []
            if not series:
                return None
            return float(series[0].get("valor"))
    except Exception:
        logger.exception("Gmail sync: mindicador.cl failed for %s", date_key)
        return None

def _get_usd_to_clp_rate(rate_date):
    cache_key = rate_date.strftime("%Y-%m-%d")
    cached = _USD_TO_CLP_CACHE.get(cache_key)
    if cached is not None:
        return cached
    rate = _fetch_usd_to_clp_exchangerate_host(cache_key)
    if rate is None:
        rate = _fetch_usd_to_clp_mindicador(rate_date)
    if rate is None:
        rate = 930.0
    _USD_TO_CLP_CACHE[cache_key] = rate
    return rate

def _parse_amount_value(value, currency):
    cleaned = value.strip()
    currency = (currency or "CLP").upper()
    if currency == "USD":
        if "," in cleaned and "." in cleaned:
            if cleaned.rfind(".") > cleaned.rfind(","):
                cleaned = cleaned.replace(",", "")
            else:
                cleaned = cleaned.replace(".", "").replace(",", ".")
        elif "," in cleaned:
            cleaned = cleaned.replace(",", ".")
        return float(cleaned)
    # CLP-style: dot as thousands, comma as decimal
    if "," in cleaned and "." in cleaned:
        if cleaned.rfind(",") > cleaned.rfind("."):
            cleaned = cleaned.replace(".", "").replace(",", ".")
        else:
            cleaned = cleaned.replace(",", "")
    elif "," in cleaned:
        cleaned = cleaned.replace(".", "").replace(",", ".")
    elif "." in cleaned:
        parts = cleaned.split(".")
        if len(parts[-1]) == 3:
            cleaned = "".join(parts)
    return float(cleaned)

def _detect_currency(text):
    if not text:
        return "CLP"
    if re.search(r"\bUS\$\b|\bUSD\b|US\$\s*\d|USD\s*\d", text, re.IGNORECASE):
        return "USD"
    return "CLP"

def _amount_to_clp(amount, currency, rate_date, context_text=""):
    if currency != "USD":
        return amount
    rate = _get_usd_to_clp_rate(rate_date)
    if rate:
        return amount * float(rate)
    logger.warning("Gmail sync: USD->CLP rate unavailable for %s", rate_date)
    return amount

def _parse_purchase_email(text):
    if not text:
        return None
    normalized = " ".join(text.split())
    try:
        primary_match = re.search(
            r"compra por\s+(?:(US\$|USD)\s*)?\$?([\d\.,]+)\s+con (?:Tarjeta de Crédito|cargo a Cuenta)\s+(\*+\d+)\s+en\s+(.+?)\s+el\s+(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2})",
            normalized,
            re.IGNORECASE,
        )
        amount_match = re.search(
            r"compra por\s+(?:(US\$|USD)\s*)?\$?([\d\.,]+)",
            normalized,
            re.IGNORECASE,
        )
        merchant_match = re.search(r"en\s+(.+?)\s+el\s+\d{2}/\d{2}/\d{4}", normalized, re.IGNORECASE)
        account_match = re.search(r"(?:Tarjeta de Crédito|Cuenta)\s+(\*+\d+)", normalized, re.IGNORECASE)
        datetime_match = re.search(r"el\s+(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2})", normalized)
    except re.error:
        logger.exception("Gmail sync: regex failed to compile")
        return None
    if not amount_match or not datetime_match:
        return None
    if primary_match:
        currency = (primary_match.group(1) or "").strip().upper() or "CLP"
        amount_raw = primary_match.group(2)
        account = primary_match.group(3).strip()
        merchant = primary_match.group(4).strip()
        date_str = primary_match.group(5)
        time_str = primary_match.group(6)
    else:
        currency = (amount_match.group(1) or "").strip().upper() or "CLP"
        amount_raw = amount_match.group(2)
        merchant = merchant_match.group(1).strip() if merchant_match else ""
        account = account_match.group(1).strip() if account_match else ""
        date_str = datetime_match.group(1)
        time_str = datetime_match.group(2)
    description = _extract_relevant_text(text) or merchant
    try:
        purchase_date = datetime.datetime.strptime(date_str, "%d/%m/%Y").date()
        datetime.datetime.strptime(time_str, "%H:%M")
    except ValueError:
        return None
    try:
        amount = _parse_amount_value(amount_raw, currency)
    except ValueError:
        return None
    if currency == "US$":
        currency = "USD"
    return {
        "amount": amount,
        "currency": currency,
        "merchant": merchant,
        "account": account,
        "description": description,
        "purchase_date": purchase_date,
    }

def _categorize_description(user, description):
    categories = list(Category.objects.filter(user=user).exclude(name="ninguna"))
    if not categories:
        return Category.objects.filter(user=user, name="ninguna").first()
    description_lower = description.lower()
    if "uber eats" in description_lower or "ubereats" in description_lower:
        for category in categories:
            if category.name.strip().lower() == "comida":
                return category
    for category in categories:
        if category.name.lower() in description_lower:
            return category
    if user.use_gpt and user.openai_api_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=user.openai_api_key)
            category_names = [cat.name for cat in categories]
            prompt = (
                "Clasifica la siguiente transaccion en una de estas categorias exactas: "
                f"{', '.join(category_names)}. Si no aplica, responde exactamente 'ninguna'. "
                f"Transaccion: {description}"
            )
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Responde solo con el nombre exacto de la categoria."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
            )
            suggestion = response.choices[0].message.content.strip()
            for category in categories:
                if suggestion.lower() == category.name.lower():
                    return category
        except Exception:
            return Category.objects.filter(user=user, name="ninguna").first()
    return Category.objects.filter(user=user, name="ninguna").first()

def _transaction_exists(user, amount, date, description, merchant="", email_received_at=None):
    if merchant:
        query = Transaction.objects.filter(
            user=user,
            amount=amount,
            date=date,
            description__icontains=merchant,
        )
    else:
        query = Transaction.objects.filter(
            user=user,
            amount=amount,
            date=date,
            description__iexact=description,
        )
    if email_received_at is not None:
        query = query.filter(email_received_at=email_received_at)
    return query.exists()

def _parse_gmail_received_at(message_payload):
    internal_date = message_payload.get("internalDate")
    if not internal_date:
        return None
    try:
        timestamp_ms = int(internal_date)
    except (TypeError, ValueError):
        return None
    return datetime.datetime.fromtimestamp(timestamp_ms / 1000, tz=datetime.timezone.utc)

def _get_gmail_service(user):
    credential = GmailCredential.objects.filter(user=user).first()
    if not credential:
        return None
    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
    except ImportError:
        return None
    creds_data = json.loads(credential.credentials_json)
    creds = Credentials.from_authorized_user_info(creds_data)
    if creds.expired and creds.refresh_token:
        try:
            from google.auth.transport.requests import Request
            creds.refresh(Request())
            credential.credentials_json = creds.to_json()
            credential.save()
        except Exception:
            return None
    return build("gmail", "v1", credentials=creds)

def _sync_gmail_range(user, start, end, page_token=None):
    service = _get_gmail_service(user)
    if not service:
        logger.warning("Gmail sync: no service for user=%s", user.id)
        return {"created": 0, "total": 0, "parsed": 0, "transactions": [], "next_page_token": None}
    query = (
        '(subject:"Compra con Tarjeta de Crédito" OR subject:"Cargo en Cuenta") '
        f'in:anywhere after:{start.strftime("%Y/%m/%d")} before:{end.strftime("%Y/%m/%d")}'
    )
    logger.info("Gmail sync query for user=%s: %s", user.id, query)
    created = 0
    total = 0
    parsed_count = 0
    created_transactions = []
    try:
        response = service.users().messages().list(userId="me", q=query, pageToken=page_token).execute()
        logger.info("Gmail sync batch user=%s messages=%s", user.id, len(response.get("messages", [])))
        messages = response.get("messages", [])
        for msg in messages:
            total += 1
            gmail_id = msg.get("id")
            existing_message = GmailMessage.objects.filter(user=user, gmail_id=gmail_id).first()
            if existing_message:
                if existing_message.purchase_date is None:
                    continue
                raw_description = (
                    existing_message.snippet
                    or existing_message.subject
                    or existing_message.merchant
                    or "Compra con tarjeta"
                )
                description = _extract_relevant_text(raw_description) or raw_description
                merchant = (existing_message.merchant or "").strip()
                detected_currency = _detect_currency(
                    f"{existing_message.subject} {existing_message.snippet}"
                )
                currency = existing_message.currency or detected_currency
                if detected_currency == "USD" and existing_message.currency != "USD":
                    existing_message.currency = "USD"
                    existing_message.save(update_fields=["currency"])
                amount_clp = _amount_to_clp(
                    existing_message.amount,
                    currency,
                    existing_message.purchase_date,
                    raw_description,
                )
                if not _transaction_exists(
                    user=user,
                    amount=amount_clp,
                    date=existing_message.purchase_date,
                    description=description,
                    merchant=merchant,
                    email_received_at=existing_message.email_received_at,
                ):
                    if currency == "USD":
                        usd_match = Transaction.objects.filter(
                            user=user,
                            amount=existing_message.amount,
                            date=existing_message.purchase_date,
                            description__iexact=description,
                        ).first()
                        if usd_match:
                            usd_match.amount = amount_clp
                            usd_match.save(update_fields=["amount"])
                            continue
                    category = _categorize_description(user, description)
                    transaction = Transaction.objects.create(
                        user=user,
                        description=description,
                        amount=amount_clp,
                        date=existing_message.purchase_date,
                        email_received_at=existing_message.email_received_at,
                        category=category,
                    )
                    created += 1
                    created_transactions.append(
                        {
                            "id": transaction.id,
                            "description": transaction.description,
                            "category": category.name if category else "ninguna",
                            "amount": transaction.amount,
                        }
                    )
                continue
            meta = service.users().messages().get(
                userId="me",
                id=gmail_id,
                format="metadata",
                metadataHeaders=["Subject"],
            ).execute()
            payload = meta.get("payload", {})
            email_received_at = _parse_gmail_received_at(meta)
            headers = payload.get("headers", [])
            subject = _get_header(headers, "Subject")
            snippet = meta.get("snippet", "")
            parsed = _parse_purchase_email(snippet)
            body_text = ""
            if not parsed:
                full = service.users().messages().get(userId="me", id=gmail_id, format="full").execute()
                payload = full.get("payload", {})
                if email_received_at is None:
                    email_received_at = _parse_gmail_received_at(full)
                body_text = _decode_gmail_body(payload)
                parsed = _parse_purchase_email(body_text or snippet)
            if not parsed:
                logger.info("Gmail sync: no parse match user=%s subject=%s snippet=%s", user.id, subject, snippet)
                continue
            parsed_count += 1
            currency = parsed.get("currency") or _detect_currency(f"{subject} {snippet}")
            amount_clp = _amount_to_clp(parsed["amount"], currency, parsed["purchase_date"], snippet)
            try:
                GmailMessage.objects.get_or_create(
                    user=user,
                    gmail_id=gmail_id,
                    defaults={
                        "subject": subject,
                        "snippet": snippet,
                        "amount": parsed["amount"],
                        "currency": currency,
                        "merchant": parsed["merchant"],
                        "account": parsed["account"],
                        "purchase_date": parsed["purchase_date"],
                        "email_received_at": email_received_at,
                    },
                )
            except IntegrityError:
                logger.info("Gmail sync: duplicate gmail_id user=%s id=%s", user.id, gmail_id)
                continue
            description = parsed.get("description") or parsed["merchant"] or subject or "Compra con tarjeta"
            merchant = (parsed.get("merchant") or "").strip()
            if not _transaction_exists(
                user=user,
                amount=amount_clp,
                date=parsed["purchase_date"],
                description=description,
                merchant=merchant,
                email_received_at=email_received_at,
            ):
                category = _categorize_description(user, description)
                transaction = Transaction.objects.create(
                    user=user,
                    description=description,
                    amount=amount_clp,
                    date=parsed["purchase_date"],
                    email_received_at=email_received_at,
                    category=category,
                )
                created += 1
                created_transactions.append(
                    {
                        "id": transaction.id,
                        "description": transaction.description,
                        "category": category.name if category else "ninguna",
                        "amount": transaction.amount,
                    }
                )
        next_page_token = response.get("nextPageToken")
        if not next_page_token:
            GmailCredential.objects.filter(user=user).update(last_synced_at=timezone.now())
    except Exception:
        logger.exception("Gmail sync failed for user=%s", user.id)
        return {
            "created": created,
            "total": total,
            "parsed": parsed_count,
            "transactions": created_transactions,
            "next_page_token": None,
        }
    return {
        "created": created,
        "total": total,
        "parsed": parsed_count,
        "transactions": created_transactions,
        "next_page_token": next_page_token,
    }

def _sync_gmail_month(user, month_date, page_token=None):
    start, end = _month_range(month_date)
    return _sync_gmail_range(user, start, end, page_token=page_token)

def index(request):
    # Cuando se carga la página
    if request.method in ('GET', 'HEAD'):
        #Por motivos de seguridad un usuario no autenticado no puede acceder a el listado
        if request.user.is_authenticated:
            # Se recupera el usuario
            user_id= request.user.id
            selected_month = request.GET.get("month")
            active_date = timezone.now().date()
            if selected_month:
                try:
                    active_date = datetime.datetime.strptime(selected_month, "%Y-%m").date()
                except ValueError:
                    active_date = timezone.now().date()
            month_start, month_end = _month_range(active_date)
            #se calcula el saldo disponible para el usuario ya logeado
            budget = 0
            gastos = Transaction.objects.filter(
                user=request.user,
                date__gte=month_start,
                date__lt=month_end,
            ).exclude(description="Transferencia interna").aggregate(Sum('amount'))['amount__sum'] or 0
            month_budget_for_balance = MonthlyBudget.objects.filter(user=request.user, month=month_start).first()
            if month_budget_for_balance and month_budget_for_balance.budget is not None:
                budget = month_budget_for_balance.budget - gastos
            # Se cargan todas las categorias del usuario
            categories = Category.objects.filter(user=user_id)
            budgets = []
            positive = []
            for cat in categories:
                saldo_cat = saldo_categoría(user_id, cat)
                if saldo_cat["valid"]:
                    positive.append(saldo_cat)
                budgets.append(saldo_cat)
            today = active_date
            month_budget = MonthlyBudget.objects.filter(user=request.user, month=month_start).first()
            if not month_budget:
                month_budget = MonthlyBudget(user=request.user, month=month_start, salary=0, budget=0)
            spends_sum = Transaction.objects.filter(
                user=request.user,
                date__gte=month_start,
                date__lt=month_end,
            ).exclude(description="Transferencia interna").aggregate(Sum('amount'))['amount__sum'] or 0
            effective_spend = max(month_budget.budget, spends_sum)
            month_savings = month_budget.salary - effective_spend
            gmail_connected = GmailCredential.objects.filter(user=request.user).exists()
            chart_labels = []
            chart_values = []
            chart_cumulative = []
            running_total = 0
            for offset in range(5, -1, -1):
                month_date = _shift_month(month_start, -offset)
                start, end = _month_range(month_date)
                budget_row = MonthlyBudget.objects.filter(user=request.user, month=start).first()
                if not budget_row:
                    budget_row = MonthlyBudget(user=request.user, month=start, salary=0, budget=0)
                spends = Transaction.objects.filter(
                    user=request.user,
                    date__gte=start,
                    date__lt=end,
                ).exclude(description="Transferencia interna").aggregate(Sum('amount'))['amount__sum'] or 0
                effective_spend = max(budget_row.budget, spends)
                month_value = budget_row.salary - effective_spend
                chart_labels.append(_month_label(start))
                chart_values.append(month_value)
                running_total += month_value
                chart_cumulative.append(running_total)
            total_withdrawals = SavingsWithdrawal.objects.filter(user=request.user).aggregate(Sum('amount'))['amount__sum'] or 0
            total_savings = sum(chart_values) - total_withdrawals
            withdrawals = SavingsWithdrawal.objects.filter(user=request.user).order_by('-date')
            #se guarda como diccionario
            context = {
                'budget': budget,
                "gastos": gastos,
                'categories': categories,
                'today': timezone.now().strftime("%Y-%m-%d"),
                'budgets': budgets,
                "positive": positive,
                'month_budget': month_budget,
                'month_label': month_start.strftime("%Y-%m"),
                'month_savings': month_savings,
                'chart_labels': json.dumps(chart_labels),
                'chart_values': json.dumps(chart_values),
                'chart_cumulative': json.dumps(chart_cumulative),
                'total_savings': total_savings,
                'withdrawals': withdrawals,
                'gmail_connected': gmail_connected,
            }
            # Se renderiza la página
            return render(request, 'index.html', context)
        # Si el usuario no está autenticado, se redirecciona al login
        else:
            return redirect('login')
    # Cuando se envía el formulario
    elif request.method == "POST":
        # Se recupera el usuario
        user = request.user
        # Se recuperan los campos del formulario
        description = request.POST['description']
        amount = request.POST['amount']
        date = request.POST['date']
        category = request.POST['category']
        if category == "__auto__":
            cat = _categorize_description(user, description)
        else:
            cat = Category.objects.filter(user=user, name=category).first()
        # Se crea un objeto transacción
        transaction = Transaction.objects.create(user=user, description=description, amount=amount, date=date, category=cat)
        transaction.save()
        # Se vuelve a la misma página
        return redirect('index')
    return redirect('login')

#-----------------------------------------------17:19------>

#---------------27/04/2023--------Diego y Gonzalo---------->
#-------------------------03/06/2023-------Felipe---------------->
#-------------------------04/06/2023-------Manuel---------------->
#-----------------------------------07/06/2023----------Felipe----->
#Función que lista las transacciones de un usuario
def list_transactions(request):
    if request.user.is_authenticated:
        # Obtener categorías del usuario
        categories = Category.objects.filter(user=request.user)
        selected_cats = request.GET.getlist('categories')
        transactions = []

        # Obtener parámetros de fecha seleccionados
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        if not start_date and not end_date:
            month_start, month_end = _month_range(timezone.now().date())
            start_date = month_start
            end_date = month_end
        cats = categories
        if selected_cats:
            cats = categories.filter(id__in=selected_cats)

        order = request.GET.get("order", "desc")
        next_order = "asc" if order == "desc" else "desc"
        toggle_params = request.GET.copy()
        toggle_params["order"] = next_order
        toggle_query = toggle_params.urlencode()

        for cat in cats:
            trans = Transaction.objects.filter(category=cat)
            if start_date and end_date:
                trans = trans.filter(date__range=[start_date, end_date])
            if order == "asc":
                trans = trans.order_by("date", "id")
            else:
                trans = trans.order_by("-date", "-id")
            transactions.append({'name': cat.name, 'trans': trans})
                
        #debe tener budgets para mostrar el estado
        budgets = []
        for cat in cats:
            budgets.append(saldo_categoría(request.user, cat))  
        # Pasar las transacciones y categorías a la plantilla
        return render(
            request,
            "listado.html",
            {
                "transactions": transactions,
                "categories": categories,
                "budgets": budgets,
                "order": order,
                "toggle_query": toggle_query,
            },
        )

    else:
        # Si no está autenticado, redirigir al inicio de sesión
        return redirect('login')


#---------------28/04/2023--------Diego y Gonzalo---------->
#Función que edita el registro de una transacción
def edit_trans(request, id_transaccion):
    #Por motivos de seguridad un usuario no autenticado no puede acceder a el listado
    if request.user.is_authenticated:
        transaccion= Transaction.objects.filter(id=id_transaccion).first()
        #El usuario asociado a la transacción debe ser el mismo que quiere realizar el edit, 
        #de lo contrario, podría editar el de otra persona
        if transaccion.user == request.user: 
            #obtenemos el formulario haciendo llamada a funcion de forms.py
            form = EditTransactionForm(user=request.user, instance = transaccion)
            #entregamos el formulario editado con su id de transacción para ser llamado en actualizar
            return render(request, "edit_trans.html", {"form": form, "transaction": transaccion})
        else:
            return redirect('list')
    #Si no está autenticado, lo mandamos a login
    else:
        return redirect('login')


#Función que actualiza una transacción en la base de datos
def actualizar_trans(request, id_transaccion):
    if request.user.is_authenticated: #Revisamos si el usuario está autenticado
        #Obtenemos la transacción con el id buscado
        transaccion = Transaction.objects.filter(id=id_transaccion).first()
        #El usuario asociado a la transacción debe ser el mismo que quiere realizar el edit, 
        #de lo contrario, podría editar el de otra persona
        if transaccion.user == request.user:
            form = EditTransactionForm(request.POST, instance = transaccion,user=request.user)
            if form.is_valid(): #Si los cambios cumplen las restricciones de los campos, guardamos los cambios
                form.save()
                transaccion = Transaction.objects.filter(id=id_transaccion).first()
        #Redirigimos hacia el listado de transacciones
        return redirect('list')
    #Si no está autenticado, lo mandamos a login
    else:
        return redirect('login')

        
#Funcion que elimina registros de transacciones
def delete_trans(request,id_transaccion):
    if request.user.is_authenticated:
        transaccion = Transaction.objects.filter(id=id_transaccion).first()
        #El usuario asociado a la transacción debe ser el mismo que quiere realizar el edit, 
        #de lo contrario, podría eliminar el de otra persona
        if transaccion.user == request.user:
            #Eliminamos y redirigimos al listado de transacciones
            transaccion.delete()
        return redirect('list')
    #Si no está autenticado, lo mandamos a login
    else:
        return redirect('login')
    
#---------------30/05/2023--------Lucas---------->
def organize_fin(request):
    # Si el usuario está autenticado
    if request.user.is_authenticated:
        # Recibimos el formulario
        if request.method == 'POST':
            # Si se tienen como campos a name y budget, es el formulario de categoría
            if 'name' in request.POST and 'budget' in request.POST:
                # Recuperamos ambos valores
                name = request.POST['name']
                # Recuperamos el presupuesto ingresado
                budget = request.POST['budget']
                # Creamos la categoría
                category = Category.objects.create(name=name, budget=budget, user=request.user)
                category.save()
                # Redirigimos al usuario a la vista organiza tus finanzas
                return redirect('organiza_finanzas')
            if 'salary' in request.POST and 'budget' in request.POST:
                month = request.POST.get('budget_month')
                try:
                    month_date = datetime.datetime.strptime(month, "%Y-%m").date()
                except (TypeError, ValueError):
                    month_date = timezone.now().date()
                month_start = _month_start(month_date)
                budget_row, _ = MonthlyBudget.objects.get_or_create(user=request.user, month=month_start)
                salary = request.POST.get('salary')
                budget = request.POST.get('budget')
                savings = request.POST.get('month_savings')
                if salary and budget:
                    budget_row.salary = float(salary or 0)
                    budget_row.budget = float(budget or 0)
                elif salary and savings:
                    budget_row.salary = float(salary or 0)
                    budget_row.budget = float(salary or 0) - float(savings or 0)
                elif budget and savings:
                    budget_row.salary = float(budget or 0) + float(savings or 0)
                    budget_row.budget = float(budget or 0)
                budget_row.save()
                return redirect('organiza_finanzas')
            if 'use_gpt' in request.POST or 'openai_api_key' in request.POST:
                request.user.use_gpt = request.POST.get('use_gpt') == 'on'
                api_key = request.POST.get('openai_api_key') or ''
                request.user.openai_api_key = api_key.strip()
                request.user.save()
                return redirect('organiza_finanzas')
        # Si estamos cargando la página
        else:
            # Cargamos las categorías del usuario
            categories = Category.objects.filter(user = request.user)
            # Cargamos la página
            month_start = _month_start(timezone.now().date())
            budget_row = MonthlyBudget.objects.filter(user=request.user, month=month_start).first()
            if not budget_row:
                budget_row = MonthlyBudget(user=request.user, month=month_start, salary=0, budget=0)
            gmail_connected = GmailCredential.objects.filter(user=request.user).exists()
            return render(
                request,
                'organiza_finanzas.html',
                {
                    'categories': categories,
                    'budget_row': budget_row,
                    'budget_month': month_start.strftime("%Y-%m"),
                    'use_gpt': request.user.use_gpt,
                    'openai_api_key': request.user.openai_api_key or '',
                    'gmail_connected': gmail_connected,
                },
            )
    # Si no está autenticado
    else:
        # Se le redirige al login
        return redirect('login')

#----------03/06/2023---------Gonzalo--------------->
#funcion que permite eliminar una categoría
def delete_cat(request,id_categoria):
    if request.user.is_authenticated:
        categoria = Category.objects.filter(id=id_categoria).first()
        #El usuario asociado a la transacción debe ser el mismo que quiere realizar el edit, 
        #de lo contrario, podría eliminar el de otra persona
        if categoria.user == request.user:
            #Eliminamos y redirigimos al listado de categorias
            categoria_ninguna = Category.objects.filter(user=request.user, name="ninguna").first()
            transacciones = Transaction.objects.filter(category=categoria)
            for transaccion in transacciones:
                transaccion.category = categoria_ninguna
                transaccion.save()

            categoria.delete()

        categories = Category.objects.filter(user = request.user)  
        return render(request, 'organiza_finanzas.html', {'categories': categories})
    #Si no está autenticado, lo mandamos a login
    else:
        return redirect('login')



#Función que edita el registro de una categoria
def edit_cat(request, id_categoria):
    #Por motivos de seguridad un usuario no autenticado no puede acceder a el listado
    if request.user.is_authenticated:
        categoria= Category.objects.filter(id=id_categoria).first()
        #El usuario asociado a la categoria debe ser el mismo que quiere realizar el edit, 
        #de lo contrario, podría editar el de otra persona
        if categoria.user == request.user: 
            #obtenemos el formulario haciendo llamada a funcion de forms.py
            budget = int(categoria.budget) if categoria.budget.is_integer() else categoria.budget
            form = EditCategoryForm(instance = categoria)
            #entregamos el formulario editado con su id de transacción para ser llamado en actualizar
            return render(request, "edit_cat.html", {"form": form, "transaction": categoria, "budget": budget})
        else:
            categories = Category.objects.filter(user = request.user)  
            return render(request, 'organiza_finanzas.html', {'categories': categories})
    #Si no está autenticado, lo mandamos a login
    else:
        return redirect('login')


#Función que actualiza una categoria en la base de datos
def actualizar_cat(request, id_categoria):
    if request.user.is_authenticated: #Revisamos si el usuario está autenticado
        #Obtenemos la transacción con el id buscado
        categoria = Category.objects.filter(id=id_categoria).first()
        #El usuario asociado a la transacción debe ser el mismo que quiere realizar el edit, 
        #de lo contrario, podría editar el de otra persona
        if categoria.user == request.user:
            form = EditCategoryForm(request.POST, instance = categoria)
            if form.is_valid():
                form.save()
                return redirect('organiza_finanzas')
            else:
                print(form.errors)
    #Si no está autenticado, lo mandamos a login
    else:
        return redirect('login')
    
# Función que permite transferir un saldo negativo a otra categoría
def transfer_debt(request, id_categoria):
    if request.user.is_authenticated: #Revisamos si el usuario está autenticado
        if request.method == "GET":
            user_id= request.user.id
            categories = Category.objects.filter(user = user_id)
            category = Category.objects.filter(user = user_id, id = id_categoria).first()
            saldo_cat = saldo_categoría(user_id, category)
            positive_cats = {}
            for c in categories:
                if c.name != "ninguna" and c.name != category.name:
                    saldo = saldo_categoría(user_id, c)
                    positive_cats[c.name] = {}
                    positive_cats[c.name]["cat"] = c
                    positive_cats[c.name]["saldo"] = saldo['amount']
            context = {"category": id_categoria, "cat_name": category.name, "categories": positive_cats, "saldo_cat": saldo_cat}
            return render(request, 'transfer_debt.html', context)
        elif request.method == "POST":
            # Si se tienen como campos a name y budget, es el formulario de categoría
            user_id= request.user.id
            categories = Category.objects.filter(user = user_id)
            category = Category.objects.filter(user = user_id, id = id_categoria).first()
            saldo_cat = saldo_categoría(user_id, category)
            modifications = request.POST.getlist('amount')
            i = 0
            for c in categories:
                if c.name != "ninguna" and c.name != category.name:
                    saldo = saldo_categoría(user_id, c)
                    if modifications[i]:
                        value = int(modifications[i])
                        if value != 0:
                            _ = Transaction.objects.create(
                                user=request.user,
                                description="Transferencia interna",
                                amount=-value,
                                date=timezone.now().strftime("%Y-%m-%d"),
                                category=c,
                            )
                            _ = Transaction.objects.create(
                                user=request.user,
                                description="Transferencia interna",
                                amount=value,
                                date=timezone.now().strftime("%Y-%m-%d"),
                                category=category,
                            )
                    i+=1
                    
            return redirect('/')
    else:
        return redirect('login')

# Función que toma una transacción generada por correo y actualiza la base de datos
@csrf_exempt
def add_transaction_email(request):
    # Estamos recibiendo una transacción nueva
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get('email')
        amount = data.get('amount')
        account = data.get('account')
        description = data.get('description')
        date = data.get('date')
        # Se recuperan los campos de la request
        email = email.split('<')[1].split('>')[0]
        user = User.objects.filter(username=email)[0]
        amount = float(amount.replace('.', '').strip("'"))
        description = description.strip("'").replace('\n', ' ')
        description = _extract_relevant_text(description) or description
        date = date.strip("'")
        # Se categoriza automaticamente cuando es posible
        cat = _categorize_description(user, description)
        # Se crea un objeto transacción
        if len(Transaction.objects.filter(user=user, amount=amount, description=description, date=date)) == 0:
            transaction = Transaction.objects.create(user=user, description=description, amount=amount, date=date, category=cat)
            transaction.save()
            # Logic to update database
        return JsonResponse({'status': 'success'})
    else:
        return JsonResponse({'status': 'error'}, status=405)

def gmail_connect(request):
    if not request.user.is_authenticated:
        return redirect('login')
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")
    if not client_id or not client_secret or not redirect_uri:
        return JsonResponse({'status': 'error', 'message': 'Missing Google OAuth env vars.'}, status=400)
    try:
        from google_auth_oauthlib.flow import Flow
    except ImportError:
        return JsonResponse({'status': 'error', 'message': 'Google auth libs not installed.'}, status=400)
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    flow.redirect_uri = redirect_uri
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    request.session["gmail_oauth_state"] = state
    return redirect(authorization_url)

def gmail_callback(request):
    if not request.user.is_authenticated:
        return redirect('login')
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")
    if not client_id or not client_secret or not redirect_uri:
        return JsonResponse({'status': 'error', 'message': 'Missing Google OAuth env vars.'}, status=400)
    try:
        from google_auth_oauthlib.flow import Flow
    except ImportError:
        return JsonResponse({'status': 'error', 'message': 'Google auth libs not installed.'}, status=400)
    state = request.session.get("gmail_oauth_state")
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        state=state,
    )
    flow.redirect_uri = redirect_uri
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    creds = flow.credentials
    gmail_user = request.user.username
    GmailCredential.objects.update_or_create(
        user=request.user,
        defaults={
            "email": gmail_user,
            "credentials_json": creds.to_json(),
            "last_synced_at": None,
        },
    )
    return redirect('index')

def gmail_sync(request):
    if not request.user.is_authenticated:
        return redirect('login')
    if not GmailCredential.objects.filter(user=request.user).exists():
        return JsonResponse({'status': 'error', 'message': 'Gmail no conectado.'}, status=400)
    month = request.GET.get("month")
    date_only = request.GET.get("date")
    resync = request.GET.get("resync") == "1"
    run_async = request.GET.get("async") == "1"
    page_token = request.GET.get("page_token")
    month_date = None
    if month:
        try:
            month_date = datetime.datetime.strptime(month, "%Y-%m").date()
        except ValueError:
            month_date = None
    if date_only:
        try:
            date_value = datetime.datetime.strptime(date_only, "%Y-%m-%d").date()
        except ValueError:
            return JsonResponse({'status': 'error', 'message': 'Fecha inválida.'}, status=400)
        start = date_value
        end = date_value + datetime.timedelta(days=1)
        if resync and not page_token:
            Transaction.objects.filter(
                user=request.user,
                date__gte=start,
                date__lt=end,
            ).delete()
            GmailMessage.objects.filter(
                user=request.user,
                purchase_date__gte=start,
                purchase_date__lt=end,
            ).delete()
        result = _sync_gmail_range(request.user, start, end, page_token=page_token)
    else:
        if not month_date:
            month_date = timezone.now().date()
        if resync and run_async:
            worker = threading.Thread(
                target=_run_gmail_month_sync,
                args=(request.user.id, month_date, True),
                daemon=True,
            )
            worker.start()
            return JsonResponse({'status': 'success', 'message': 'Resync started.'})
        if resync and not page_token:
            month_start, month_end = _month_range(_month_start(month_date))
            Transaction.objects.filter(
                user=request.user,
                date__gte=month_start,
                date__lt=month_end,
            ).delete()
            GmailMessage.objects.filter(
                user=request.user,
                purchase_date__gte=month_start,
                purchase_date__lt=month_end,
            ).delete()
        result = _sync_gmail_month(request.user, _month_start(month_date), page_token=page_token)
    return JsonResponse({'status': 'success', **result})

def gmail_sync_cron(request):
    token = request.headers.get("X-Sync-Token") or request.GET.get("token")
    expected = os.environ.get("SYNC_CRON_TOKEN")
    if not expected or token != expected:
        return JsonResponse({'status': 'error', 'message': 'Unauthorized.'}, status=401)
    lock_name = "gmail_sync_cron"
    if not _acquire_cron_lock(lock_name):
        return JsonResponse({'status': 'skipped', 'message': 'Cron already running.'})
    today = timezone.now().date()
    start = today - timedelta(days=7)
    end = today + timedelta(days=1)
    summaries = []
    try:
        for credential in GmailCredential.objects.select_related("user").all():
            user = credential.user
            total_created = 0
            total_reviewed = 0
            total_parsed = 0
            page_token = None
            pages = 0
            while pages < 25:
                result = _sync_gmail_range(user, start, end, page_token=page_token)
                total_created += result.get("created", 0)
                total_reviewed += result.get("total", 0)
                total_parsed += result.get("parsed", 0)
                page_token = result.get("next_page_token")
                pages += 1
                if not page_token:
                    break
            summaries.append(
                {
                    "user_id": user.id,
                    "created": total_created,
                    "total": total_reviewed,
                    "parsed": total_parsed,
                    "pages": pages,
                    "complete": page_token is None,
                }
            )
    finally:
        _release_cron_lock(lock_name)
    return JsonResponse({'status': 'success', 'summaries': summaries})

@csrf_exempt
def suggest_category(request):
    if request.method != "POST":
        return JsonResponse({'status': 'error'}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({'status': 'error'}, status=401)
    data = json.loads(request.body or '{}')
    description = data.get('description', '')
    category = _categorize_description(request.user, description)
    return JsonResponse({'status': 'success', 'category': category.name if category else 'ninguna'})

def add_savings_withdrawal(request):
    if not request.user.is_authenticated:
        return redirect('login')
    if request.method != "POST":
        return redirect('index')
    date = request.POST.get('date')
    amount = request.POST.get('amount')
    note = request.POST.get('note', '')
    if date and amount:
        SavingsWithdrawal.objects.create(user=request.user, date=date, amount=amount, note=note)
    return redirect('index')
        
