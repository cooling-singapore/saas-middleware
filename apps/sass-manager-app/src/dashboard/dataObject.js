import React from 'react';
import styled from 'styled-components';
import { Draggable } from 'react-beautiful-dnd';
import { Button, 
    Card, 
    CardContent, 
    CardActions,
    CardHeader,
    Tooltip,
    IconButton
} from "@material-ui/core";

import MoreVertIcon from '@material-ui/icons/MoreVert';

const Container = styled(Card)`
border-radius: 0;
margin-bottom: 8px;
margin-top: 8px;
background-color: ${props => 
    (props.isDragDisabled ? 'lightgrey' :
    props.isDragging ? 'lightgreen' : 'white')};
`;

const Title = styled.div`
    font-size: small;
    font-weight: bold;
`;

const Type = styled.div`
    font-size: x-small;
`;

export default function DataObject(props) {
    return ( 
    <Draggable 
    draggableId={props.item.id} 
    index={props.index}>
        {(provided, snapshot) => (
            <Container
                {...provided.draggableProps}
                {...provided.dragHandleProps}
                ref={provided.innerRef}
                isDragging={snapshot.isDragging}
            >
                <CardHeader
                    action={
                    <Tooltip title="Show Data Object">
                        <IconButton aria-label="show-data-object">
                            <MoreVertIcon />
                        </IconButton>
                    </Tooltip>
                    }
                    title={<Title>{props.item.name}</Title>}
                    subheader={<Type>{props.item.type}</Type>}
                />
            </Container>
        )}
    </Draggable>
    ); 
}