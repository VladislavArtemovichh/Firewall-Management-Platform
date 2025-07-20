#!/usr/bin/env python3
"""
Скрипт для оптимизации производительности базы данных

Использование:
    python scripts/optimize_database.py
"""

import sys
import os
import asyncio
import logging

# Добавляем корневую директорию проекта в путь
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database_indexes import optimize_database_performance, get_index_usage_statistics

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('database_optimization.log')
    ]
)

async def main():
    """Основная функция для запуска оптимизации"""
    print("🚀 Запуск оптимизации базы данных...")
    print("=" * 50)
    
    try:
        # Запускаем полную оптимизацию
        await optimize_database_performance()
        
        print("\n✅ Оптимизация завершена успешно!")
        print("=" * 50)
        
        # Получаем статистику использования индексов
        print("\n📊 Статистика использования индексов:")
        print("-" * 30)
        stats = await get_index_usage_statistics()
        
        if stats:
            for stat in stats[:10]:  # Показываем топ-10 индексов
                print(f"📈 {stat['tablename']}.{stat['indexname']}")
                print(f"   Сканирований: {stat['index_scans']}")
                print(f"   Прочитано записей: {stat['tuples_read']}")
                print(f"   Получено записей: {stat['tuples_fetched']}")
                print()
        else:
            print("📝 Статистика пока недоступна (индексы еще не использовались)")
        
        print("\n🎯 Рекомендации по дальнейшей оптимизации:")
        print("1. Мониторьте производительность запросов")
        print("2. Анализируйте медленные запросы")
        print("3. Рассмотрите возможность партиционирования больших таблиц")
        print("4. Настройте автоматическую очистку старых данных")
        
    except Exception as e:
        print(f"\n❌ Ошибка при оптимизации: {e}")
        logging.error(f"Database optimization failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 