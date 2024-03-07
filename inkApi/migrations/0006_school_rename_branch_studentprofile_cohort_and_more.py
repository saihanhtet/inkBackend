# Generated by Django 4.2.6 on 2024-03-05 03:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('inkApi', '0005_rename_branch_name_cohort_cohort_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='School',
            fields=[
                ('school_id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('location', models.CharField(max_length=255)),
            ],
        ),
        migrations.RenameField(
            model_name='studentprofile',
            old_name='branch',
            new_name='cohort',
        ),
        migrations.AddField(
            model_name='adminprofile',
            name='school',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='admin_profiles', to='inkApi.school'),
        ),
        migrations.AddField(
            model_name='studentprofile',
            name='school',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='students', to='inkApi.school'),
        ),
        migrations.AddField(
            model_name='teacherprofile',
            name='school',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='teacher_profiles', to='inkApi.school'),
        ),
    ]
