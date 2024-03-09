python .\manage.py makemigrations --settings=inkBackend.settings.dev
python .\manage.py migrate --settings=inkBackend.settings.dev
python .\manage.py runserver --settings=inkBackend.settings.dev