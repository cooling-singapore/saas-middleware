import React from 'react';
import styled from 'styled-components';
import {
    Card,
    CardContent,
    CardActions,
    Typography,
    makeStyles
} from '@material-ui/core';

const Container = styled(Card)`
    border-radius: 0;
    margin-bottom: 8px;
    margin-top: 8px;
`
const useStyles = makeStyles((theme) => ({
    noTextTransform: {
        textTransform: 'none'
    },
}));

export default function Key({data}) {
    const classes = useStyles();
    console.log(data);
    return (
        <Container variant="outlined">
            <CardContent>
                <Typography variant="body2">
                    Type: {data.type}
                </Typography>
                <Typography variant="body2">
                    Institution: {data.institution}
                </Typography>
            </CardContent>
        </Container>
    );
}