from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model import Category, Base, CateItem, User

DB_URL = 'postgresql://root:root@127.0.0.1:5432/catalog'
engine = create_engine(DB_URL, echo=True)
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

user1 = User(username="troy")
user1.hash_password('qwer1234')
session.add(user1)
session.commit()

category1 = Category(name="Soccer", user_id=1)
session.add(category1)
session.commit()

category2 = Category(name="Basketball", user_id=1)
session.add(category2)
session.commit()

category3 = Category(name="Baseball", user_id=1)
session.add(category3)
session.commit()

category4 = Category(name="Frisbee", user_id=1)
session.add(category4)
session.commit()

category5 = Category(name="Snowboarding", user_id=1)
session.add(category5)
session.commit()

cateitem1 = CateItem(name="Goggles",
                     category=category5,
                     description="this is Goggles Snowboarding",
                     user=user1)
session.add(cateitem1)
session.commit()

cateitem2 = CateItem(name="Snowboard",
                     category=category5,
                     description="this is Snowboard Snowboarding",
                     user=user1)
session.add(cateitem2)
session.commit()

category6 = Category(name="Rock Climbing", user_id=1)
session.add(category6)
session.commit()

category7 = Category(name="Foosball", user_id=1)
session.add(category7)
session.commit()

category8 = Category(name="Skating", user_id=1)
session.add(category8)
session.commit()

category9 = Category(name="Hockey", user_id=1)
session.add(category9)
session.commit()
