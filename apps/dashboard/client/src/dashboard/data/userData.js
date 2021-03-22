const userData = {
    keys: {
        "key1": {dataObjectId: 1},
        "key2": {dataObjectId: 2},
        "key3": {dataObjectId: 3},
        "key4": {dataObjectId: 4},
        "key5": {dataObjectId: 5},
        "key6": {dataObjectId: 6},
        "key7": {dataObjectId: 7},
        "key8": {dataObjectId: 8},
        "key9": {dataObjectId: 9}
    },

    users: {
        "admin1@test.com" : {email: "admin1@test.com", 
            password: "admin1", role: "admin", keys: [
                "key1", "key2", "key3", "key4", "key5", "key6", "key7", "key8", "key9"
            ]
        },
        "user1@test.com" : {email: "user1@test.com", password: "user1", role: "user", keys: [
            "key1"
        ]},
        "user2@test.com" : {email: "user2@test.com", password: "user2", role: "user", keys: [
            "key2", "key3"
        ]}
    },

    userIndex: [ 
        "admin1@test.com",
        "user1@test.com",
        "user2@test.com" 
    ]
} 

export default userData;