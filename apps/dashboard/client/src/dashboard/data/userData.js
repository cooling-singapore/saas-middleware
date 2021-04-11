const userData = {

    dataKeyIndex: [
        "Admin", "URA", "HDB", "NPARK", "USER"
    ],

    dataKey: {
        "Admin": {
            name: "Admin",
            keyScope: "Global"
        },
        "URA": {
            name: "URA",
            keyScope: "URA"
        },
        "HDB": {
            name: "HDB",
            keyScope: "HDB"
        },
        "NPARK": {
            name: "NPARK",
            keyScope: "NPARK"
        },
        "USER": {
            name: "USER",
            keyScope: "USER"
        },
    },

    users: {
        "admin1@test.com" : {email: "admin1@test.com", name: "Admin One", password: "admin1", role: "Admin", dataKeys: ["Admin"]},
        "user1@test.com" : {email: "user1@test.com", name: "User One", password: "user1", role: "User", dataKeys: ["USER", "URA"]},
        "user2@test.com" : {email: "user2@test.com", name: "User Two", password: "user2", role: "User",dataKeys: ["USER", "HDB"]},
        "user3@test.com" : {email: "user3@test.com", name: "User Three", password: "user3", role: "User",dataKeys: ["USER", "NPARK"]},
        "user4@test.com" : {email: "user4@test.com", name: "User Four", password: "user4", role: "User",dataKeys: ["USER", "URA", "HDB", "NPARK"]},
        "user5@test.com" : {email: "user5@test.com", name: "User Five", password: "user4", role: "User",dataKeys: ["USER", "NPARK", "HDB"]},
        "user6@test.com" : {email: "user6@test.com", name: "User Six", password: "user5", role: "User",dataKeys: ["USER"]},
        "user7@test.com" : {email: "user7@test.com", name: "User Seven", password: "user6", role: "User",dataKeys: ["USER"]}
    },

    userIndex: [ 
        "admin1@test.com",
        "user1@test.com",
        "user2@test.com",
        "user3@test.com",
        "user4@test.com",
        "user5@test.com",
        "user6@test.com",
        "user7@test.com"   
    ]
} 

export default userData;