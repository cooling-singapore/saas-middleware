import React from 'react';
import styled from 'styled-components';

import { 
    Divider,
    IconButton,
    Tooltip,
    Grid
} from "@material-ui/core";
import MoreVertIcon from '@material-ui/icons/MoreVert';

const Type = styled.div`
    font-size: x-small;
`;

const BoldType = styled(Type)`
    font-weight: bold;
`;

export default function Job(props) {
    const handleDetailClick = () => {
        console.log("handle detail");
    };
    return (
        <div>
            <Grid container
            spacing={2}
            direction='row'
            justify='space-between'
            alignItems='center'>
            <Grid item>
                <Type>{props.value.description} </Type>
                <BoldType>{props.value.status} </BoldType>
            </Grid>
            <Grid>
                <Tooltip title="Show Job Detail"> 
                    <IconButton aria-label="job-detail" onClick={handleDetailClick}>
                        <MoreVertIcon fontSize="small" />
                    </IconButton>
                </Tooltip>
            </Grid>  
            </Grid>
            <Divider />
        </div>
    );
}