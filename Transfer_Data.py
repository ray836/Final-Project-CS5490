import json


class TransferData:
    read_data = {}
    private_data = {}
    write_data = {}

    def __init__(self, read_data, private_data, write_data):
        self.read_data = read_data
        self.private_data = private_data
        self.write_data = write_data

    def to_marine_data(self):
        return MarineData(self.read_data["user_id"],
                          self.private_data["location"],
                          self.private_data["task_force"],
                          self.write_data["status_description"])

    def to_dictionary(self):
        return {"data_transfer": {"read_data": self.read_data,
                                  "private_data": self.private_data,
                                  "write_data": self.write_data}}


def get_data_from_file(file_location):
    with open(file_location) as f:
        data = json.load(f)
    return data


def write_to_file(file_location, dictionary_list):
    with open(file_location, 'w') as json_file:
        json.dump(dictionary_list, json_file)


# Example of writing/reading data to file
test_dat = [{"cool": "what"},{"ool": "hat"}]
write_to_file("test.json", test_dat)
from_file = get_data_from_file("test.json")
print(from_file)
print(from_file[0]["cool"])


class MarineData:
    def __init__(self, user_id, location, task_force, status_description):
        self.user_id = user_id
        self.location = location
        self.task_force = task_force
        self.status_description = status_description

    def to_transfer_data(self):
        t_data = TransferData({"user_id": self.user_id},
                              {"location": self.location, "task_force": self.task_force},
                              {"status_description": self.status_description})
        return t_data

    def to_dict(self):
        return {"user_id": self.user_id,
                "location": self.location,
                "task_force": self.task_force,
                "status_description": self.status_description}


# Example of how data could be used
test_marine = MarineData("Ray Grant", (1, 2), "ground force", "Moving troops North.")
print(test_marine.to_dict())
print(test_marine.to_transfer_data().to_dictionary())
print(test_marine.location[0])
print(test_marine.to_transfer_data().to_dictionary()["data_transfer"]["private_data"]["location"][0])
print(test_marine.to_transfer_data().to_marine_data().to_dict())
