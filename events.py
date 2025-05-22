from abc import ABC, abstractmethod

# Event base class
class Event:
    pass

# Specific event classes
class UserRegistered(Event):
    def __init__(self, user_id: int, email: str):
        self.user_id = user_id
        self.email = email

class OrderCreated(Event):
    def __init__(self, order_id: int, user_id: int, amount: float):
        self.order_id = order_id
        self.user_id = user_id
        self.amount = amount

# Subscriber interface
class EventSubscriber(ABC):
    @abstractmethod
    def handle_event(self, event: Event):
        pass

# Event dispatcher
class EventDispatcher:
    def __init__(self):
        self.subscribers = {}

    def subscribe(self, event_type: type, subscriber: EventSubscriber):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(subscriber)

    def dispatch(self, event: Event):
        for subscriber in self.subscribers.get(type(event), []):
            subscriber.handle_event(event)

# Example subscribers
class SendWelcomeEmailSubscriber(EventSubscriber):
    def handle_event(self, event: Event):
        if isinstance(event, UserRegistered):
            print(f"Sending welcome email to {event.email}")

class UpdateOrderStatsSubscriber(EventSubscriber):
    def handle_event(self, event: Event):
        if isinstance(event, OrderCreated):
            print(f"Updating stats for order {event.order_id} with amount {event.amount}")
