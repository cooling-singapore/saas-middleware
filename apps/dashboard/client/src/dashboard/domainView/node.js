import React from 'react';
import styled from 'styled-components';
import { Droppable } from 'react-beautiful-dnd';
import {
    Divider,
    Grid
} from '@material-ui/core';

import Processor from './processor';
import DataObject from './dataObject';

const Title = styled.h6`
    padding: 4px;
`;

const Container = styled(Grid)`
    margin-left: 4px;
    flex-grow: 1;
    width: 220px
`;

const List = styled.div`
    flex-grow: 1;
    background-color: ${props => (props.isDraggingOver ? 'skyblue' : '#F4F4F4')};
    min-height: 135px;
`;


export default function Node(props) {
    const onDeleteProcessor = (processorId) => {
        props.onDeleteProcessor(processorId, props.node.id);
    }

    return (
        // TODO: background color should be changed in the styled setting, however it was not working.
        <Container item style={{ backgroundColor: '#F4F4F4' }}>
            <Title>{props.node.title}</Title>
            <Divider />
            <Droppable droppableId={props.node.id + "processor"}
                type={'processor'}
                isDropDisabled={false}
            >
                {(provided, snapshot) => (
                    <List
                        ref={provided.innerRef}
                        {...provided.droppableProps}
                        isDraggingOver={snapshot.isDraggingOver}
                    >
                        {props.processors.map((processor, index) => <Processor key={processor.id} item={processor} nodeName={props.node.title} onDeleteProcessor={onDeleteProcessor} index={index} />)}
                        {provided.placeholder}
                    </List>
                )}
            </Droppable>
            <Divider />
            <Droppable droppableId={props.node.id + "dataObject"}
                type={'dataObject'}
                isDropDisabled={false}
            >
                {(provided, snapshot) => (
                    <List
                        ref={provided.innerRef}
                        {...provided.droppableProps}
                        isDraggingOver={snapshot.isDraggingOver}
                    >
                        {props.dataObjects.map((dataObject, index) => <DataObject key={dataObject.id} item={dataObject} index={index} />)}
                        {provided.placeholder}
                    </List>
                )}
            </Droppable>
        </Container>
    );

}