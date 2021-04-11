import React from 'react';
import userData from '../data/userData';
import styled from 'styled-components';
import {
    Grid,
    Card,
    IconButton,
    Tooltip
} from '@material-ui/core';
import User from "./user";
import { PersonAdd } from '@material-ui/icons';

// TODO: abstract duplicated divs
const Content = styled.div`
    height:100%,
`;

const Container = styled(Card)`
    border-radius: 0;
    margin-bottom: 8px;
    margin-top: 8px;
`

export default function AdminView() {
    const [userInfo, setUserInfo] = React.useState(userData);

    const onDeleteKey = (user, k) => {
        const newDataKeys = user.dataKeys.filter((key) => key !== k);
        const newUser = {
            ...user,
            dataKeys: newDataKeys
        };

        const newUserInfo = {
            ...userInfo,
            users: {
                ...userInfo.users,
                [newUser.email] : newUser
            }
        };
        
        setUserInfo(newUserInfo);
    };

    const onAddKey = (user, k) => {
        // const newDataKeys = user.dataKeys.filter((key) => key !== k);
        // const newUser = {
        //     ...user,
        //     dataKeys: newDataKeys
        // };

        // const newUserInfo = {
        //     ...userInfo,
        //     users: {
        //         ...userInfo.users,
        //         [newUser.email] : newUser
        //     }
        // };
        
        // setUserInfo(newUserInfo);
    };

    const onDeleteUser = (user) => {
        const newUserIndex = userInfo.userIndex.filter((key) => key !== user.email);

        // TODO check can we delete the state directly
        const newUsers = userInfo.users;
        delete newUsers[user.email];
        
        const newUserInfo = {
            ...userInfo,
            users: newUsers,
            userIndex: newUserIndex
        };

        setUserInfo(newUserInfo);
    }

    const onAddUser = (user) => {
        const newUsers = {
            ...userInfo.users,
            [user.email] : user
        }

        const newUserIndex = userInfo.userIndex;
        newUserIndex.push(user.email);

        const newUserInfo = {
            ...userInfo,
            users: newUsers,
            userIndex: newUserIndex
        };

        setUserInfo(newUsers);
    }

    return (
        <Content>
            <Grid
                container
                spacing={2}
                direction='row'
            >
                {/* <Grid item xs={2}>
                    <Typography variant="subtitle2" component="span">
                        Keys
                    </Typography>
                    <Divider />
                    {userInfo.keyIndex.map(index => {
                        const key = userInfo.keys[index];
                        return (
                            <Key data={key} />
                        );
                    })}
                </Grid> */}
                <Grid item xs={10}>
                    <Grid container 
                        spacing={2} 
                        direction='row'
                    >
                        {userInfo.userIndex.map(index => {
                            const user = userInfo.users[index];
                            return (
                                (user.role !== "Admin") && <User user={user} keyIndex={userInfo.dataKeyIndex} onDeleteKey={onDeleteKey} onDeleteUser={onDeleteUser}/>
                            );
                        })}
                        <Grid item xs={3}>
                            <Tooltip title="Add User">
                            <IconButton aria-label="Delete" style={{margin: '10px'}}>
                                <PersonAdd fontSize="large" onClick={handleAddUser} />
                            </IconButton>
                            </Tooltip>
                        </Grid>
                    </Grid>
                </Grid>
            </Grid>
        </Content>
    );
}