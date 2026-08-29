import asyncio
from .database import db
from .regulatory_monitor import run_forever

async def main():
    await db.connect()
    try:
        await run_forever()
    finally:
        await db.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
