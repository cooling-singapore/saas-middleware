import React from 'react';
import styled from 'styled-components';
import { Draggable } from 'react-beautiful-dnd';
import {
    Card, 
    CardContent, 
    FormControl,
    Typography,
    Select
} from '@material-ui/core';

const Container = styled(Card)`
    border-radius: 0;
    margin-bottom: 8px;
    margin-top: 8px;
    background-color: ${props => 
        (props.isDragDisabled ? 'lightgrey' :
        props.isDragging ? 'lightgreen' : 'white')};
`;

const VersionSelect = styled(Select)`
    margin-top: 8px;
    margin-left: 8px;
    width: 100px;
    height: 18px;
    font-Size: small;
`;

const Option = styled.option`
    font-Size: small;
`

export default function Processor(props) {
    const [version, setVersion] = React.useState('Version');

    const handleChange = (event) => {
        console.log(event.target.value);
        setVersion(event.target.value);
    };

    return (
        <Draggable 
        draggableId={props.item.name} 
        index={props.index}>
            {(provided, snapshot) => (
                <Container 
                {...provided.draggableProps}
                {...provided.dragHandleProps}
                ref={provided.innerRef}
                isDragging={snapshot.isDragging}>
                <CardContent>
                    <Typography variant="subtitle2" gutterBottom>
                        {props.item.type}
                    </Typography>
                    <FormControl>
                        <Typography variant='body2' color='textSecondary'>
                        Version
                        <VersionSelect native value={version} onChange={handleChange}>
                            {props.item.versions.map((version, index) => <Option key={index} value={version.id}>{version.id}</Option>)}
                        </VersionSelect>
                        </Typography>
                    </FormControl>
                </CardContent>
                </Container>
            )}
        </Draggable>
    ); 

}