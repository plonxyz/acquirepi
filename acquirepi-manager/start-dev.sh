#!/bin/bash
# Start acquirepi Manager in development mode

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting acquirepi Manager (Development Mode)"
echo "=========================================="
echo ""
echo "Starting Redis..."
redis-server &
REDIS_PID=$!

echo "Starting Django development server..."
source venv/bin/activate
python manage.py runserver 0.0.0.0:8000 &
DJANGO_PID=$!

echo "Starting mDNS service..."
python manage.py mdns_advertise &
MDNS_PID=$!

echo ""
echo "Services started:"
echo "  Redis: PID $REDIS_PID"
echo "  Django: PID $DJANGO_PID"
echo "  mDNS: PID $MDNS_PID"
echo ""
echo "Access web interface at: http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop all services..."

# Wait for Ctrl+C
trap "kill $REDIS_PID $DJANGO_PID $MDNS_PID 2>/dev/null; exit" SIGINT SIGTERM
wait
