# Инструкция: сборка, запуск, тесты

> ⚠️ **DRAFT / ALPHA.** Проект в ранней альфа-версии. Инструкция описывает тестовую сборку;
> не используйте приложение на рабочих системах без резервных копий.

## Требования

- Windows 10 (21H2+) или Windows 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) — для сборки
- Права администратора — для большинства действий (службы, реестр, задачи планировщика)

## Сборка

```powershell
git clone https://github.com/moongrail/ScanSysDefence.git
cd ScanSysDefence
dotnet build ScanSysDefence.sln -c Release
```

Результат: `ScanSysDefence.UI\bin\Release\net8.0-windows\ScanSysDefence.UI.exe`.

## Запуск

```powershell
.\ScanSysDefence.UI\bin\Release\net8.0-windows\ScanSysDefence.UI.exe
```

Если .NET установлен в пользовательский каталог (per-user SDK), задайте переменную окружения:

```powershell
$env:DOTNET_ROOT = "$env:LOCALAPPDATA\Microsoft\dotnet"
.\ScanSysDefence.UI\bin\Release\net8.0-windows\ScanSysDefence.UI.exe
```

## Тесты

```powershell
dotnet test ScanSysDefence.Tests\ScanSysDefence.Tests.csproj -c Release
```

- Тесты рассчитаны на Windows (WMI, службы, планировщик); на других ОС Windows-регрессии
  пропускаются.
- EICAR-тест создаёт тестовый файл в `%TEMP%`. Если антивирус блокирует его чтение,
  добавьте `%TEMP%` в исключения (или отключите защиту в тестовой VM) — иначе тест
  определения EICAR будет пропущен средой.
- Тестирование проекта проводилось **только в VirtualBox** (Windows 10 LTSC); на
  хост-системе выполнялась только сборка.

## Известные ограничения (alpha)

- Часть функций требует прав администратора; без них кнопки неактивны и показывают причину.
- «Создать точку восстановления» не выполняется автоматически — только по запросу.
- Куки, сессии и пароли браузеров не удаляются.
- Интерфейс и названия элементов могут меняться между версиями.

## Структура решения

```
ScanSysDefence.sln
├── ScanSysDefence.Core      — модели, сканеры, анализ рисков, ремедиация, карантин
├── ScanSysDefence.Native    — Win32 P/Invoke (реестр, безопасность)
├── ScanSysDefence.UI        — WPF-приложение (MVVM)
└── ScanSysDefence.Tests     — xUnit-тесты (49)
```
