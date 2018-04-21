import pickle
import time


class Cache:
    def __init__(self):
        self.cache = dict(dict())
        self.load_cache()

    def save_cache(self):
        with open('cache.txt', 'wb') as file:
            try:
                pickle.dump(self.cache, file)
            except pickle.PicklingError:
                print("Can't pickle")
            except Exception as e:
                print(e)

    def load_cache(self):
        with open('cache.txt', 'rb') as file:
            try:
                cache = pickle.load(file)
                self.cache = cache
            except pickle.UnpicklingError:
                print('File corrupted')
            except FileNotFoundError:
                print("No such file for unpickling")
            except Exception as e:
                print(e)

    def append(self, key, answer, answer_type):
        if key not in self.cache:
            self.cache[key] = {answer_type: [(answer, time.time() + answer.ttl)]}
        else:
            if answer_type in self.cache[key]:
                self.cache[key][answer_type].append((answer, time.time() + answer.ttl))
            else:
                self.cache[key][answer_type] = [(answer, time.time() + answer.ttl)]

    def __contains__(self, item):
        if item.name in self.cache:
            if item.type in self.cache[item.name]:
                for answer in self.cache[item.name][item.type]:
                    if answer[1] < time.time():
                        self.cache[item.name].pop(item.type)
                        return False
                return True
